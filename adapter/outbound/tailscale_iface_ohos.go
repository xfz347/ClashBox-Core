//go:build ohos

package outbound

/*
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
*/
import "C"

import (
	"net"
	"unsafe"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tailscale/net/netmon"
)

// OHOS(鸿蒙)沙箱不允许 netlink(NETLINK_ROUTE), Go 的 net.Interfaces()/Interface.Addrs()
// 会报 "route ip+net: netlinkrib: permission denied", 且 tailscale 的 netmon 也无法用 netlink。
//
// 这里改用 POSIX getifaddrs()(不依赖 netlink)枚举真实接口与地址, 保证:
//   - 接口名/索引/标志真实
//   - 附带真实 IP(含子网掩码), 避免"假接口无地址"导致 tailscale 认为网络不可用而卡在 NeedsLogin
// 顺序兜底: getifaddrs → /proc/net/dev → 最小接口集。
const ohosPatchInterfaceGetter = true

func registerOhosInterfaceGetter() {
	netmon.RegisterInterfaceGetter(func() (nif []netmon.Interface, err error) {
		if nif = ifaddrsInterfaces(); len(nif) > 0 {
			return nif, nil
		}
		ifaces, ierr := net.Interfaces()
		if ierr == nil && len(ifaces) > 0 {
			return wrapInterfaces(ifaces), nil
		}
		log.Warnln("[Tailscale] getifaddrs/net.Interfaces 均不可用(%v), 使用最小接口集", ierr)
		return minimalOhosInterfaces(), nil
	})
}

// ifaddrsInterfaces 通过 getifaddrs() 枚举接口与地址(不使用 netlink)
func ifaddrsInterfaces() []netmon.Interface {
	var head *C.struct_ifaddrs
	if C.getifaddrs(&head) != 0 || head == nil {
		return nil
	}
	defer C.freeifaddrs(head)

	type ent struct {
		idx   int
		name  string
		flags net.Flags
		addrs []net.Addr
	}
	order := make([]string, 0, 8)
	m := make(map[string]*ent, 8)

	for p := head; p != nil; p = p.ifa_next {
		if p.ifa_name == nil {
			continue
		}
		name := C.GoString(p.ifa_name)
		e, ok := m[name]
		if !ok {
			e = &ent{
				idx:   int(C.if_nametoindex(p.ifa_name)),
				name:  name,
				flags: linkFlags(uint32(p.ifa_flags)),
			}
			m[name] = e
			order = append(order, name)
		}
		if p.ifa_addr == nil {
			continue
		}
		switch int(p.ifa_addr.sa_family) {
		case C.AF_INET:
			sa := (*C.struct_sockaddr_in)(unsafe.Pointer(p.ifa_addr))
			ip := ipv4FromSAddr(uint32(sa.sin_addr.s_addr))
			bits := 32
			if p.ifa_netmask != nil {
				nm := (*C.struct_sockaddr_in)(unsafe.Pointer(p.ifa_netmask))
				bits = maskBits(uint32(nm.sin_addr.s_addr))
			}
			e.addrs = append(e.addrs, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, 32)})
		case C.AF_INET6:
			sa6 := (*C.struct_sockaddr_in6)(unsafe.Pointer(p.ifa_addr))
			b := (*[16]byte)(unsafe.Pointer(&sa6.sin6_addr))
			ip := make(net.IP, 16)
			copy(ip, b[:])
			bits := 128
			if p.ifa_netmask != nil {
				nm6 := (*C.struct_sockaddr_in6)(unsafe.Pointer(p.ifa_netmask))
				mb := (*[16]byte)(unsafe.Pointer(&nm6.sin6_addr))
				bits = maskBits6(mb[:])
			}
			if !ip.IsLinkLocalUnicast() {
				e.addrs = append(e.addrs, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, 128)})
			}
		}
	}

	out := make([]netmon.Interface, 0, len(order))
	for _, name := range order {
		e := m[name]
		iff := &net.Interface{Index: e.idx, Name: e.name, MTU: 1500, Flags: e.flags}
		// ★ AltAddrs 必须非 nil: 否则 netmon 会退回 net.Interface.Addrs() → netlink → EPERM
		alt := e.addrs
		if alt == nil {
			alt = []net.Addr{}
		}
		out = append(out, netmon.Interface{Interface: iff, AltAddrs: alt})
	}
	return out
}

// wrapInterfaces 统一构造 netmon.Interface(始终设置 AltAddrs, 避免 netlink 取址)
func wrapInterfaces(ifaces []net.Interface) []netmon.Interface {
	nif := make([]netmon.Interface, 0, len(ifaces))
	for i := range ifaces {
		iff := ifaces[i]
		alt := []net.Addr{}
		if iff.Flags&net.FlagLoopback != 0 {
			alt = append(alt, &net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)})
		}
		nif = append(nif, netmon.Interface{Interface: &iff, AltAddrs: alt})
	}
	return nif
}

// minimalOhosInterfaces 最小接口集(最终兜底)
func minimalOhosInterfaces() []netmon.Interface {
	lo := &net.Interface{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback | net.FlagRunning}
	eth := &net.Interface{Index: 2, Name: "eth0", MTU: 1500, Flags: net.FlagUp | net.FlagRunning}
	return []netmon.Interface{
		{Interface: lo, AltAddrs: []net.Addr{&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}}},
		{Interface: eth, AltAddrs: []net.Addr{}},
	}
}

// ipv4FromSAddr 把 sockaddr_in.sin_addr.s_addr(网络字节序)转为 net.IP
func ipv4FromSAddr(v uint32) net.IP {
	b := (*[4]byte)(unsafe.Pointer(&v))
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// maskBits 网络字节序掩码 → 前缀位数(IPv4)
func maskBits(v uint32) int {
	b := (*[4]byte)(unsafe.Pointer(&v))
	bits := 0
	for _, x := range b {
		for i := 7; i >= 0; i-- {
			if x&(1<<uint(i)) != 0 {
				bits++
			} else {
				return bits
			}
		}
	}
	return bits
}

// maskBits6 IPv6 掩码 → 前缀位数
func maskBits6(b []byte) int {
	bits := 0
	for _, x := range b {
		for i := 7; i >= 0; i-- {
			if x&(1<<uint(i)) != 0 {
				bits++
			} else {
				return bits
			}
		}
	}
	return bits
}

// linkFlags 与 anet 保持一致(Linux IFF_* 位)
func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&0x1 != 0 { // IFF_UP
		f |= net.FlagUp
	}
	if rawFlags&0x2 != 0 { // IFF_BROADCAST
		f |= net.FlagBroadcast
	}
	if rawFlags&0x8 != 0 { // IFF_LOOPBACK
		f |= net.FlagLoopback
	}
	if rawFlags&0x10 != 0 { // IFF_POINTOPOINT
		f |= net.FlagPointToPoint
	}
	if rawFlags&0x40 != 0 { // IFF_RUNNING
		f |= net.FlagRunning
	}
	if rawFlags&0x1000 != 0 { // IFF_MULTICAST
		f |= net.FlagMulticast
	}
	return f
}
