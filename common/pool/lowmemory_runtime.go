//go:build !with_low_memory

package pool

import "sync/atomic"

// 标准模式与低内存模式的缓冲区大小(运行时切换)
const (
	relaySizeStandard  = 256 * 1024
	udpSizeStandard    = 64 * 1024
	relaySizeLowMemory = 16 * 1024
	udpSizeLowMemory   = 8 * 1024
)

var lowMemoryMode atomic.Bool

// SetLowMemoryMode 运行时切换低内存缓冲模式:
// 开启后降低每条连接/会话的 TCP(Relay) 与 UDP 缓冲, 减少内存占用;
// 关闭后恢复标准缓冲。幂等, 状态未变化时不写。
func SetLowMemoryMode(low bool) {
	if lowMemoryMode.Swap(low) == low {
		return
	}
	if low {
		RelayBufferSize = relaySizeLowMemory
		UDPBufferSize = udpSizeLowMemory
	} else {
		RelayBufferSize = relaySizeStandard
		UDPBufferSize = udpSizeStandard
	}
}

// IsLowMemoryMode 当前是否处于低内存缓冲模式
func IsLowMemoryMode() bool {
	return lowMemoryMode.Load()
}

// SetUltraLowMemoryMode 内存压力最高档: relay/UDP 缓冲降到 2KB, 进一步压缩内存峰值。
// 关闭时回到低内存档(如果仍处于低内存模式)或标准档。
func SetUltraLowMemoryMode(ultra bool) {
	if ultra {
		RelayBufferSize = 2 * 1024
		UDPBufferSize = 2 * 1024
		return
	}
	if lowMemoryMode.Load() {
		RelayBufferSize = relaySizeLowMemory
		UDPBufferSize = udpSizeLowMemory
	} else {
		RelayBufferSize = relaySizeStandard
		UDPBufferSize = udpSizeStandard
	}
}
