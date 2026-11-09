//go:build ohos

package mptcp

import "net"

// OHOS 上 MPTCP 对应用不可用(IPPROTO_MPTCP 连接会挂起直到超时),
// 因此忽略 mptcp 配置, 始终使用普通 TCP, 避免订阅里 mptcp: true 的节点全部测速超时/无法连接。
const MultipathTCPAvailable = false

func SetNetDialer(dialer *net.Dialer, open bool) {}

func GetNetDialer(dialer *net.Dialer) bool {
	return false
}

func SetNetListenConfig(listenConfig *net.ListenConfig, open bool) {}

func GetNetListenConfig(listenConfig *net.ListenConfig) bool {
	return false
}
