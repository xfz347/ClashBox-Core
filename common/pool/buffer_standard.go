//go:build !with_low_memory

package pool

// 说明: 改为 var 以便运行时通过 SetLowMemoryMode 切换(见 lowmemory_runtime.go)。
var (
	// RelayBufferSize using for tcp
	// io.Copy default buffer size is 32 KiB
	RelayBufferSize = 32 * 1024

	// UDPBufferSize using for udp
	// Most UDPs are smaller than the MTU, and the TUN's MTU
	// set to 9000, so the UDP Buffer size set to 16Kib
	UDPBufferSize = 16 * 1024
)
