//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface/anet"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	ts "github.com/metacubex/tailscale"
	"github.com/metacubex/tailscale/envknob"
	"github.com/metacubex/tailscale/hostinfo"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tsnet"
	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

type Tailscale struct {
	*Base
	server      *tsnet.Server
	dnsResolver *dns.Resolver
	option      TailscaleOption
	ctx         context.Context
	cancel      context.CancelFunc
	startOnce   sync.Once
	startErr    error

	backendInitOnce sync.Once
	backendInitCh   chan struct{}
	backendInitErr  error

	serverStarted bool

	unregisterDNSResolver func()
}

type TailscaleOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Hostname   string `proxy:"hostname,omitempty"`
	AuthKey    string `proxy:"auth-key,omitempty"`
	ControlURL string `proxy:"control-url,omitempty"`
	StateDir   string `proxy:"state-dir,omitempty"`
	Ephemeral  bool   `proxy:"ephemeral,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	AcceptRoutes           *bool  `proxy:"accept-routes,omitempty"`
	ExitNode               string `proxy:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool  `proxy:"exit-node-allow-lan-access,omitempty"`
}

func init() {
	hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		versionDotTxt := strings.TrimSpace(ts.VersionDotTxt)
		hi.IPNVersion = fmt.Sprintf("%s-%s-%s", versionDotTxt, C.MihomoName, C.Version)
	})
	envknob.SetNoLogsNoSupport()
	if runtime.GOOS == "android" { // Android SDK 30 no longer permits Go's net.Interfaces to work (Issue 2293)
		netmon.RegisterInterfaceGetter(func() (nif []netmon.Interface, err error) {
			log.Debugln("[Tailscale] InterfaceGetter: start, IsForceAnet: %v", anet.IsForceAnet())
			ifaces, err := anet.Interfaces()
			if err != nil {
				log.Warnln("[Tailscale] anet.Interfaces failed: %v", err)
				return nil, err
			}
			for _, iff := range ifaces {
				addrs, err := anet.InterfaceAddrsByInterface(&iff)
				if err != nil {
					log.Warnln("[Tailscale] anet.InterfaceAddrsByInterface(%v) failed: %v", iff.Name, err)
					continue
				}
				nif = append(nif, netmon.Interface{
					Interface: &net.Interface{
						Index:        iff.Index,
						MTU:          iff.MTU,
						Name:         iff.Name,
						HardwareAddr: iff.HardwareAddr,
						Flags:        iff.Flags,
					},
					AltAddrs: addrs,
				})
			}

			log.Debugln("[Tailscale] InterfaceGetter: %v", lo.Map(nif, func(item netmon.Interface, index int) string {
				var addrs any
				addrs, err := item.Addrs()
				if err != nil {
					addrs = err
				}
				return fmt.Sprintf("{Name: %s, Addrs: %v, IsUp: %v, IsLoopback: %v}", item.Name, addrs, item.IsUp(), item.IsLoopback())
			}))
			return
		})
	}
	// ★ OHOS: 沙箱无 netlink 权限, 注册不依赖 netlink 的接口获取器, 避免 tsnet 初始化失败
	if ohosPatchInterfaceGetter {
		registerOhosInterfaceGetter()
	}
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	if _, err := buildTailscaleMaskedPrefs(option); err != nil {
		return nil, err
	}
	// ★ 诊断: 打印解析后的关键选项(accept-routes/exit-node 是否生效)
	ar := "unset"
	if option.AcceptRoutes != nil {
		if *option.AcceptRoutes {
			ar = "true"
		} else {
			ar = "false"
		}
	}
	lanAcc := "unset"
	if option.ExitNodeAllowLANAccess != nil {
		if *option.ExitNodeAllowLANAccess {
			lanAcc = "true"
		} else {
			lanAcc = "false"
		}
	}
	akState := "empty"
	if option.AuthKey != "" {
		akState = "set"
	}
	log.Debugln("[Tailscale](%s) 选项: hostname=%q stateDir=%q acceptRoutes=%s authKey=%s exitNode=%q exitNodeAllowLAN=%s controlURL=%q ephemeral=%v udp=%v",
		option.Name, option.Hostname, option.StateDir, ar, akState, option.ExitNode, lanAcc, option.ControlURL, option.Ephemeral, option.UDP)
	if option.StateDir == "" {
		option.StateDir = "tailscale"
	}
	option.StateDir = C.Path.Resolve(option.StateDir)
	if !C.Path.IsSafePath(option.StateDir) {
		return nil, C.Path.ErrNotSafePath(option.StateDir)
	}

	addr := option.ControlURL
	if addr == "" {
		addr = "tailscale"
	}
	ctx, cancel := context.WithCancel(context.Background())
	outbound := &Tailscale{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Tailscale,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:        option,
		ctx:           ctx,
		cancel:        cancel,
		backendInitCh: make(chan struct{}),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.server = &tsnet.Server{
		Dir:        option.StateDir,
		Hostname:   option.Hostname,
		AuthKey:    option.AuthKey,
		ControlURL: option.ControlURL,
		Ephemeral:  option.Ephemeral,
		SystemDialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			log.Debugln("[Tailscale](%s) SystemDialer: start dial %s %s", option.Name, network, address)
			conn, err := outbound.dialer.DialContext(ctx, network, address)
			log.Debugln("[Tailscale](%s) SystemDialer: finish dial %s %s, err: %v", option.Name, network, address, err)
			return conn, err
		},
		SystemPacketListener: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			log.Debugln("[Tailscale](%s) SystemPacketListener: start listen %s %s", option.Name, network, address)
			pc, err := outbound.dialer.ListenPacket(ctx, network, address, netip.AddrPort{})
			log.Debugln("[Tailscale](%s) SystemPacketListener: finish listen %s %s, err: %v", option.Name, network, address, err)
			return pc, err
		},
		ExtraRootCAs: ca.GetCertPool(),
		LookupHook: func(ctx context.Context, host string) ([]netip.Addr, error) {
			log.Debugln("[Tailscale](%s) LookupHook: start lookup %s", option.Name, host)
			ips, err := resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
			log.Debugln("[Tailscale](%s) LookupHook: finish lookup %s, ips: %v, err: %v", option.Name, host, ips, err)
			return ips, err
		},
		UserLogf: func(format string, args ...any) {
			log.Infoln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			log.Infoln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
	}
	dnsTransport := tailscaleDNSTransport{tailscale: outbound}
	outbound.dnsResolver = dns.NewResolverFromClient(dnsTransport)
	outbound.unregisterDNSResolver = dns.RegisterTailscaleDnsClient(option.Name, dnsTransport)
	// ★ 立即在后台启动 tsnet(而非等首次拨号), 便于尽早完成登录注册并暴露诊断日志
	go func() {
		outbound.controlConnectivitySelfTest()
		if err := outbound.start(); err != nil {
			log.Warnln("[Tailscale](%s) 后台启动失败: %v", option.Name, err)
		}
	}()
	return outbound, nil
}

func (t *Tailscale) start() error {
	t.startOnce.Do(func() {
		if err := t.server.Start(); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		t.serverStarted = true
		ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
		defer cancel()
		if err := t.applyPrefs(ctx); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		go t.watchBackendState()
		go t.statusProbeLoop()
	})
	return t.startErr
}

func (t *Tailscale) ensureStarted(ctx context.Context) error {
	if err := t.start(); err != nil {
		return err
	}
	return t.waitBackendInitialized(ctx)
}

// statusProbeLoop 每 60s 打印一次 tailscale 后端状态, 便于在日志中随时看到当前状态
// (NeedsLogin / Stopped / Running) 与已发现节点数, 定位"无法访问内网"类问题。
func (t *Tailscale) statusProbeLoop() {
	tk := time.NewTicker(120 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-tk.C:
			lc, err := t.server.LocalClient()
			if err != nil {
				log.Debugln("[Tailscale](%s) 状态巡检失败(LocalClient): %v", t.Name(), err)
				continue
			}
			st, err := lc.Status(t.ctx)
			if err != nil {
				log.Debugln("[Tailscale](%s) 状态巡检失败(Status): %v", t.Name(), err)
				continue
			}
			selfIPs := ""
			if st.Self != nil {
				selfIPs = fmt.Sprintf("%v", st.Self.TailscaleIPs)
			}
			log.Infoln("[Tailscale](%s) 状态巡检: state=%s peers=%d self=%s", t.Name(), st.BackendState, len(st.Peer), selfIPs)
			if len(st.Health) > 0 {
				n := len(st.Health)
				if n > 5 {
					n = 5
				}
				for i := 0; i < n; i++ {
					log.Warnln("[Tailscale](%s) 健康: %s", t.Name(), st.Health[i])
				}
			}
			if st.AuthURL != "" {
				log.Warnln("[Tailscale](%s) 需要授权登录, 请在浏览器打开完成授权: %s", t.Name(), st.AuthURL)
			}
			if st.BackendState != "Running" {
				log.Warnln("[Tailscale](%s) 未就绪(state=%s): 若为 NeedsLogin 请在出站配置填写 auth-key; 未运行则无法访问 tailnet/子网路由", t.Name(), st.BackendState)
			}
		}
	}
}

// controlConnectivitySelfTest 自检: 经内核 dialer 拨 controlplane.tailscale.com:443,
// 结果直接反映"控制面是否可达"(登录必须依赖此链路)。
func (t *Tailscale) controlConnectivitySelfTest() {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	target := "controlplane.tailscale.com:443"
	conn, err := t.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Warnln("[Tailscale](%s) 控制面连通性自检失败(%s): %v", t.Name(), target, err)
		return
	}
	_ = conn.Close()
	log.Infoln("[Tailscale](%s) 控制面连通性自检成功(%s)", t.Name(), target)
}

func (t *Tailscale) watchBackendState() {	lc, err := t.server.LocalClient()
	if err != nil {
		t.setBackendInitialized(err)
		return
	}
	watcher, err := lc.WatchIPNBus(t.ctx, ipn.NotifyInitialState)
	if err != nil {
		t.setBackendInitialized(err)
		return
	}
	defer watcher.Close()

	backendInitialized := false
	exitNodeNeedsStatus := tailscaleExitNodeNeedsStatus(t.option)
	for {
		n, err := watcher.Next()
		if err != nil {
			t.setBackendInitialized(err)
			return
		}
		if n.State == nil {
			continue
		}
		log.Infoln("[Tailscale](%s) 后端状态: %v", t.Name(), *n.State)
		if *n.State == ipn.NeedsLogin {
			log.Warnln("[Tailscale](%s) 节点未登录(NeedsLogin): 请在出站配置中填写 auth-key(在 Tailscale 后台 Settings→Keys 生成)后重载配置, 否则无法访问 tailnet/子网路由", t.Name())
		}

		if *n.State != ipn.NoState && !backendInitialized {
			t.setBackendInitialized(nil)
			backendInitialized = true
			if !exitNodeNeedsStatus {
				return
			}
		}
		if exitNodeNeedsStatus && *n.State == ipn.Running {
			if err := t.applyExitNodePrefs(t.ctx); err != nil {
				log.Warnln("[Tailscale](%s) set exit node failed: %v", t.Name(), err)
			}
			return
		}
	}
}

func (t *Tailscale) setBackendInitialized(err error) {
	t.backendInitOnce.Do(func() {
		t.backendInitErr = err
		close(t.backendInitCh)
	})
}

func (t *Tailscale) waitBackendInitialized(ctx context.Context) error {
	select {
	case <-t.backendInitCh:
		return t.backendInitErr
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ctx.Done():
		return t.ctx.Err()
	}
}

func (t *Tailscale) applyPrefs(ctx context.Context) error {
	mp, err := buildTailscaleMaskedPrefs(t.option)
	if err != nil {
		return err
	}
	if mp == nil {
		return nil
	}
	log.Debugln("[Tailscale](%s) 应用偏好: routeAll=%v(set=%v) exitNode=%q autoExitNode=%q allowLan=%v",
		t.Name(), mp.RouteAll, mp.RouteAllSet, t.option.ExitNode, mp.AutoExitNode, mp.ExitNodeAllowLANAccess)
	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func (t *Tailscale) applyExitNodePrefs(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	mp := &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
	}
	if t.option.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess = *t.option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
	}
	if err = mp.SetExitNodeIP(t.option.ExitNode, status); err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func buildTailscaleMaskedPrefs(option TailscaleOption) (*ipn.MaskedPrefs, error) {
	var mp ipn.MaskedPrefs
	changed := false

	if option.AcceptRoutes != nil {
		mp.RouteAll = *option.AcceptRoutes
		mp.RouteAllSet = true
		changed = true
	}
	if option.ExitNode != "" {
		if autoExitNode, ok := ipn.ParseAutoExitNodeString(option.ExitNode); ok {
			mp.AutoExitNode = autoExitNode
			mp.AutoExitNodeSet = true
			changed = true
		}
	}
	if option.ExitNodeAllowLANAccess != nil && !tailscaleExitNodeNeedsStatus(option) {
		mp.ExitNodeAllowLANAccess = *option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
		changed = true
	}
	if !changed {
		return nil, nil
	}
	return &mp, nil
}

func tailscaleExitNodeNeedsStatus(option TailscaleOption) bool {
	if option.ExitNode == "" {
		return false
	}
	_, ok := ipn.ParseAutoExitNodeString(option.ExitNode)
	return !ok
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	netStack, err := t.server.Netstack(ctx)
	if err != nil {
		return nil, err
	}
	v4, v6 := t.server.TailscaleIPs()
	options := t.DialOptions()
	options = append(options, dialer.WithResolver(t.dnsResolver))
	options = append(options, dialer.WithNetDialer(dialer.NetDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dst, err := netip.ParseAddrPort(address) // the dialer will resolve the domain to ip
		if err != nil {
			return nil, err
		}
		src := v4
		if dst.Addr().Is6() {
			src = v6
		}
		tcpConn, err := netStack.DialContextTCPWithBind(ctx, src, dst)
		if err != nil {
			return nil, err
		}
		return tcpConn, nil
	})))
	var conn net.Conn
	conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, t), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	v4, v6 := t.server.TailscaleIPs()
	src := v4
	if metadata.DstIP.Is6() {
		src = v6
	}
	pc, err := t.server.ListenPacket("udp", net.JoinHostPort(src.String(), "0"))
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(pc, t), nil
}

func (t *Tailscale) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, t.prefer, t.dnsResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

type tailscaleDNSTransport struct {
	tailscale *Tailscale
}

func (t tailscaleDNSTransport) Address() string {
	return "tailscale://" + t.tailscale.Name()
}

func (t tailscaleDNSTransport) ResetConnection() {}

func (t tailscaleDNSTransport) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	if err := t.tailscale.ensureStarted(ctx); err != nil {
		return nil, err
	}
	q := msg.Question[0]
	qtypeName, ok := D.TypeToString[q.Qtype]
	if !ok {
		return nil, fmt.Errorf("unsupported query type: %d", q.Qtype)
	}
	lc, err := t.tailscale.server.LocalClient()
	if err != nil {
		return nil, err
	}
	response, _, err := lc.QueryDNS(ctx, q.Name, qtypeName)
	if err != nil {
		return nil, err
	}
	var responseMsg D.Msg
	if err = responseMsg.Unpack(response); err != nil {
		return nil, err
	}
	responseMsg.Id = msg.Id
	return &responseMsg, nil
}

func (t *Tailscale) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func (t *Tailscale) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (t *Tailscale) Close() error {
	t.cancel()
	if t.unregisterDNSResolver != nil {
		t.unregisterDNSResolver()
	}
	t.startOnce.Do(func() {
		t.startErr = errors.New("tailscale outbound closed")
	})
	if t.server != nil && t.serverStarted { // tsnet.Server.Close() must not be called before or concurrently with Start.
		return t.server.Close()
	}
	return nil
}
