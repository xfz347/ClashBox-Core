package outbound

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	lazyStackIdleRelease     = 10 * time.Minute
	lazyStackScanInterval    = time.Minute
	lazyStackRehandshakeGap  = 50 * time.Millisecond
	lazyStackReleaseSettle   = 2 * time.Second
	lazyStackSettlePollStep  = 10 * time.Millisecond
)

// stackSessionUse 重协议出站的会话引用计数: dialing 保护拨号期间不被释放,
// conns 保护已建立连接期间不被释放, lastActive 记录最近一次成功建立连接的时间。
type stackSessionUse struct {
	mu         sync.Mutex
	dialing    int
	conns      int
	lastActive time.Time
}

func (u *stackSessionUse) enter() {
	u.mu.Lock()
	u.dialing++
	u.mu.Unlock()
}

func (u *stackSessionUse) leaveDial() {
	u.mu.Lock()
	u.dialing--
	u.mu.Unlock()
}

func (u *stackSessionUse) opened() func() {
	u.mu.Lock()
	u.conns++
	u.lastActive = time.Now()
	u.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			u.mu.Lock()
			u.conns--
			u.lastActive = time.Now()
			u.mu.Unlock()
		})
	}
}

func (u *stackSessionUse) lastUsed() time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastActive
}

type refCountedConn struct {
	net.Conn
	closeHook func()
	closeOnce sync.Once
}

func (c *refCountedConn) Close() error {
	c.closeOnce.Do(c.closeHook)
	return c.Conn.Close()
}

type refCountedPacketConn struct {
	net.PacketConn
	closeHook func()
	closeOnce sync.Once
}

func (c *refCountedPacketConn) Close() error {
	c.closeOnce.Do(c.closeHook)
	return c.PacketConn.Close()
}

type lazyStackEntry struct {
	name     string
	lastUsed func() time.Time
	release  func() bool
}

var (
	lazyStackRegistryMu sync.Mutex
	lazyStackRegistry   = map[string]*lazyStackEntry{}
	lazyStackScanOnce   sync.Once
)

func registerLazyStack(e *lazyStackEntry) {
	lazyStackScanOnce.Do(startLazyStackScanner)
	lazyStackRegistryMu.Lock()
	lazyStackRegistry[e.name] = e
	lazyStackRegistryMu.Unlock()
}

func unregisterLazyStack(name string) {
	lazyStackRegistryMu.Lock()
	delete(lazyStackRegistry, name)
	lazyStackRegistryMu.Unlock()
}

func startLazyStackScanner() {
	go func() {
		ticker := time.NewTicker(lazyStackScanInterval)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			lazyStackRegistryMu.Lock()
			entries := make([]*lazyStackEntry, 0, len(lazyStackRegistry))
			for _, e := range lazyStackRegistry {
				entries = append(entries, e)
			}
			lazyStackRegistryMu.Unlock()
			for _, e := range entries {
				if now.Sub(e.lastUsed()) >= lazyStackIdleRelease {
					if e.release() {
						log.Infoln("[LazyStack] released idle stack of %s (idle >= %s)", e.name, lazyStackIdleRelease)
					}
				}
			}
		}
	}()
}

// ipStackMayRefuse 拒绝畸形本地地址/MTU: 前缀重复、未指定/组播地址、越界 MTU、广播地址
func ipStackMayRefuse(localPrefixes []netip.Prefix, mtu uint32) bool {
	if mtu != 0 && (mtu < 68 || mtu > 65535) {
		return true
	}
	for i, prefix := range localPrefixes {
		for _, other := range localPrefixes[i+1:] {
			if prefix.Addr() == other.Addr() {
				return true
			}
		}
		address := prefix.Addr().Unmap()
		if !prefix.IsValid() || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
			return true
		}
		bits := prefix.Bits()
		if prefix.Addr().Is6() && address.Is4() {
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() {
			return true
		}
		if address.Is4() && ipv4MayBeBroadcast(address, bits) {
			return true
		}
	}
	for i, prefix := range localPrefixes {
		address := prefix.Addr().Unmap()
		if !address.Is4() {
			continue
		}
		for j, other := range localPrefixes {
			otherAddress := other.Addr().Unmap()
			bits := other.Bits()
			if other.Addr().Is6() && otherAddress.Is4() {
				bits -= 96
			}
			if i == j || !otherAddress.Is4() || bits < 0 || bits >= 31 {
				continue
			}
			if network, err := otherAddress.Prefix(bits); err == nil && network.Contains(address) && ipv4MayBeBroadcast(address, bits) {
				return true
			}
		}
	}
	return false
}

func ipv4MayBeBroadcast(address netip.Addr, bits int) bool {
	value := address.As4()
	all := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	if all == ^uint32(0) {
		return true
	}
	if bits >= 31 {
		return false
	}
	hostMask := uint32((uint64(1) << (32 - bits)) - 1)
	return all&hostMask == hostMask
}

var errIPStackRefused = errors.New("invalid local addresses or mtu for IP stack")
