package mitm

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

// 脚本执行内存准入(对齐 ProjectClash 的模块内存阶梯):
// 可用内存过低时直接跳过脚本执行(请求/响应按原样透传), 而不是在 OOM 边缘
// 继续起脚本运行时。
//
// - floor: 低于它时按脚本体量估算本次执行成本, 不够就跳过
// - relief: 高于它才恢复正常执行
// - hold: 触发后 30s 内保持跳过, 避免内存抖动导致脚本反复启停
const (
	scriptMemoryFloorBytes  = 96 * 1024 * 1024
	scriptMemoryReliefBytes = 128 * 1024 * 1024
	scriptBaseCostBytes     = 8 * 1024 * 1024
	scriptCostFactor        = 4
	scriptMemoryHoldSeconds = 30
)

var (
	lastSkipLogAt atomic.Int64
	skippedTotal  atomic.Int64
	// lowMemoryUntil: 触发阶梯后保持跳过的截止时间(unix 秒)
	lowMemoryUntil atomic.Int64
)

// scriptMemoryAvailable 读取 MemAvailable(字节)。
func scriptMemoryAvailable() (uint64, bool) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// scriptShouldSkip 按"可用内存 + 脚本体量 + 滞回"判断是否跳过脚本。
func scriptShouldSkip(pattern string, scriptBytes int) bool {
	now := time.Now().Unix()
	if lowMemoryUntil.Load() > now {
		skippedTotal.Add(1)
		return true
	}
	avail, ok := scriptMemoryAvailable()
	if !ok {
		return false
	}
	// 内存充足时直接放行
	if avail >= scriptMemoryReliefBytes {
		return false
	}
	cost := uint64(scriptBaseCostBytes)
	if scriptBytes > 0 {
		cost += uint64(scriptBytes) * scriptCostFactor
	}
	if avail > scriptMemoryFloorBytes+cost {
		return false
	}
	lowMemoryUntil.Store(now + scriptMemoryHoldSeconds)
	n := skippedTotal.Add(1)
	nowUnix := time.Now().Unix()
	last := lastSkipLogAt.Load()
	if nowUnix-last >= 30 && lastSkipLogAt.CompareAndSwap(last, nowUnix) {
		log.Warnln("[MITM] scripts skipped for low memory: %s available, script=%dB, %d skipped so far (pattern %s)",
			formatMiB(avail), scriptBytes, n, pattern)
	}
	return true
}

func formatMiB(bytes uint64) string {
	return strconv.FormatUint(bytes/(1024*1024), 10) + "MiB"
}
