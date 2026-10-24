package mitm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// Cron schedule matching is done per-minute with a 30s ticker so that
// short-lived inaccuracies never cause a missed run. A script runs at most
// once per matching minute.

type cronEntry struct {
	script  CronScript
	lastRun time.Time
}

var (
	cronMu        sync.Mutex
	cronEntries   []cronEntry
	cronTicker    *time.Ticker
	cronStop      chan struct{}
	cronTunActive bool
)

// UpdateCronScripts replaces the scheduled script set. A nil/empty set stops
// the scheduler and releases the ticker goroutine. The ticker only runs when
// TUN is active (see SetCronTunActive), so cron does not fire before VPN start.
func UpdateCronScripts(scripts []CronScript) {
	cronMu.Lock()
	defer cronMu.Unlock()

	cronEntries = cronEntries[:0]
	for _, s := range scripts {
		if s.Enabled && strings.TrimSpace(s.Content) != "" && cronScheduleValid(s.Schedule) {
			cronEntries = append(cronEntries, cronEntry{script: s})
		}
	}

	reconcileCronTickerLocked()
}

// SetCronTunActive is called by the host when the TUN interface starts/stops,
// so cron scripts only run while the VPN connection is actually up.
func SetCronTunActive(active bool) {
	cronMu.Lock()
	defer cronMu.Unlock()
	if cronTunActive == active {
		return
	}
	cronTunActive = active
	reconcileCronTickerLocked()
}

// reconcileCronTickerLocked starts/stops the ticker based on (has scripts && TUN active).
// Caller must hold cronMu.
func reconcileCronTickerLocked() {
	shouldRun := len(cronEntries) > 0 && cronTunActive
	if shouldRun && cronTicker == nil {
		cronTicker = time.NewTicker(30 * time.Second)
		cronStop = make(chan struct{})
		go cronLoop(cronTicker, cronStop)
		log.Infoln("[cron] scheduler started with %d script(s)", len(cronEntries))
		return
	}
	if !shouldRun && cronTicker != nil {
		cronTicker.Stop()
		cronTicker = nil
		close(cronStop)
		cronStop = nil
		log.Infoln("[cron] scheduler stopped")
	}
}

func cronLoop(t *time.Ticker, stop chan struct{}) {
	for {
		select {
		case <-t.C:
			tickCron()
		case <-stop:
			return
		}
	}
}

func tickCron() {
	now := time.Now()
	minuteStart := now.Truncate(time.Minute)

	cronMu.Lock()
	entries := make([]cronEntry, len(cronEntries))
	copy(entries, cronEntries)
	cronMu.Unlock()

	for i := range entries {
		e := &entries[i]
		if !cronMatches(e.script.Schedule, now) {
			continue
		}
		// Guard: run at most once per minute.
		if !e.lastRun.IsZero() && !e.lastRun.Before(minuteStart) {
			continue
		}
		e.lastRun = now
		script := e.script
		go runCronScript(script)
	}
}

func runCronScript(script CronScript) {
	defer func() {
		if r := recover(); r != nil {
			log.Warnln("[cron] script %q panic: %v", script.Name, r)
			writeCronNotify(script.Name, false)
		}
	}()
	if ExternalScriptExecutor == nil {
		log.Warnln("[cron] script %q skipped: script engine not initialized", script.Name)
		return
	}
	start := time.Now()
	result, err := ExternalScriptExecutor(Script{
		Phase:    "cron",
		Pattern:  script.Schedule,
		Content:  script.Content,
		Argument: script.Argument,
		Engine:   "quickjs",
	}, nil, nil, nil)
	if err != nil {
		log.Warnln("[cron] script %q failed: %v", script.Name, err)
		writeCronNotify(script.Name, false)
		return
	}
	writeCronNotify(script.Name, true)
	if result != nil {
		log.Debugln("[cron] script %q finished in %s", script.Name, time.Since(start))
	} else {
		log.Debugln("[cron] script %q finished in %s (no result)", script.Name, time.Since(start))
	}
}

// writeCronNotify 记录最近一次 cron 运行结果，供 VPN 进程读取后发通知。
func writeCronNotify(name string, success bool) {
	dir := constant.Path.HomeDir()
	if dir == "" {
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"name":      name,
		"timestamp": time.Now().UnixMilli(),
		"success":   success,
	})
	_ = os.WriteFile(filepath.Join(dir, "cron-notify.json"), payload, 0600)
}

func cronScheduleValid(schedule string) bool {
	fields := strings.Fields(schedule)
	return len(fields) == 5
}

func cronMatches(schedule string, t time.Time) bool {
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return false
	}
	return matchCronField(fields[0], t.Minute(), 0, 59) &&
		matchCronField(fields[1], t.Hour(), 0, 23) &&
		matchCronField(fields[2], t.Day(), 1, 31) &&
		matchCronField(fields[3], int(t.Month()), 1, 12) &&
		matchCronField(fields[4], int(t.Weekday()), 0, 6)
}

func matchCronField(field string, value, min, max int) bool {
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if matchCronPart(part, value, min, max) {
			return true
		}
	}
	return false
}

func matchCronPart(part string, value, min, max int) bool {
	if part == "*" || part == "?" {
		return true
	}
	if idx := strings.IndexByte(part, '/'); idx >= 0 {
		base := part[:idx]
		step, err := strconv.Atoi(part[idx+1:])
		if err != nil || step <= 0 {
			return false
		}
		lo, hi := min, max
		if base != "*" && base != "?" {
			var ok bool
			lo, hi, ok = parseCronRange(base, min, max)
			if !ok {
				return false
			}
		}
		for v := lo; v <= hi; v += step {
			if v == value {
				return true
			}
		}
		return false
	}
	if idx := strings.IndexByte(part, '-'); idx >= 0 {
		lo, hi, ok := parseCronRange(part, min, max)
		if !ok {
			return false
		}
		return value >= lo && value <= hi
	}
	n, err := strconv.Atoi(part)
	if err != nil {
		return false
	}
	return n == value
}

func parseCronRange(part string, min, max int) (int, int, bool) {
	idx := strings.IndexByte(part, '-')
	if idx < 0 {
		n, err := strconv.Atoi(part)
		if err != nil {
			return 0, 0, false
		}
		if n < min || n > max {
			return 0, 0, false
		}
		return n, n, true
	}
	lo, err1 := strconv.Atoi(part[:idx])
	hi, err2 := strconv.Atoi(part[idx+1:])
	if err1 != nil || err2 != nil || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}
