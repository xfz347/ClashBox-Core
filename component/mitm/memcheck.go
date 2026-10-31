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
// 继续起 goja 运行时。阈值取 96MiB, 低于它时只保留代理转发能力。

const scriptMemoryFloorBytes = 96 * 1024 * 1024

var (
	lastSkipLogAt atomic.Int64
	skippedTotal  atomic.Int64
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

// scriptShouldSkip 内存不足时返回 true(带日志节流, 最多每 30s 一条)。
func scriptShouldSkip(pattern string) bool {
	avail, ok := scriptMemoryAvailable()
	if !ok || avail >= scriptMemoryFloorBytes {
		return false
	}
	n := skippedTotal.Add(1)
	now := time.Now().Unix()
	last := lastSkipLogAt.Load()
	if now-last >= 30 && lastSkipLogAt.CompareAndSwap(last, now) {
		log.Warnln("[MITM] scripts skipped for low memory: %s available, %d skipped so far (pattern %s)",
			formatMiB(avail), n, pattern)
	}
	return true
}

func formatMiB(bytes uint64) string {
	return strconv.FormatUint(bytes/(1024*1024), 10) + "MiB"
}
