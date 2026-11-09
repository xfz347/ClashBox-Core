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
	log.Warnln("[cron] update: total=%d", len(scripts))

	cronEntries = cronEntries[:0]
	for _, s := range scripts {
		if s.Enabled && strings.TrimSpace(s.Content) != "" && cronScheduleValid(s.Schedule) {
			cronEntries = append(cronEntries, cronEntry{script: s})
			log.Warnln("[cron] entry accepted: name=%q schedule=%q len(content)=%d", s.Name, s.Schedule, len(s.Content))
		} else {
			log.Warnln("[cron] entry skipped: name=%q schedule=%q enabled=%v len(content)=%d", s.Name, s.Schedule, s.Enabled, len(s.Content))
		}
	}

	reconcileCronTickerLocked()
}

// SetCronTunActive is called by the host when the TUN interface starts/stops,
// so cron scripts only run while the VPN connection is actually up.
func SetCronTunActive(active bool) {
	cronMu.Lock()
	defer cronMu.Unlock()
	log.Warnln("[cron] SetCronTunActive=%v", active)
	if cronTunActive == active {
		return
	}
	cronTunActive = active
	reconcileCronTickerLocked()
}

// reconcileCronTickerLocked starts/stops the ticker based on (has scripts && TUN active).
// Caller must hold cronMu.
func reconcileCronTickerLocked() {
	log.Warnln("[cron] reconcile: entries=%d tunActive=%v running=%v", len(cronEntries), cronTunActive, cronTicker != nil)
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

// cronLocation: OHOS 应用进程的 TZ 常为 UTC(未设置 TZ 且无 /etc/localtime),
// 而用户按本地时间设置 cron, 必须用本地时区(东八区)参与匹配。
var cronLocation = time.FixedZone("CST", 8*3600)

func tickCron() {
	now := time.Now().In(cronLocation)
	minuteStart := now.Truncate(time.Minute)

	// ★ 必须在锁内直接修改 cronEntries 上的 lastRun:
	//   之前把 entries 复制到局部切片再改 lastRun, 改动随切片丢弃,
	//   "每分钟最多执行一次"去重失效, */1 会每 30s(每次 tick)执行一次。
	var toRun []CronScript
	cronMu.Lock()
	for i := range cronEntries {
		e := &cronEntries[i]
		if !cronMatches(e.script.Schedule, now) {
			continue
		}
		if !e.lastRun.IsZero() && !e.lastRun.Before(minuteStart) {
			continue
		}
		e.lastRun = now
		log.Warnln("[cron] fire script=%q schedule=%q at=%s", e.script.Name, e.script.Schedule, now.Format("15:04"))
		toRun = append(toRun, e.script)
	}
	cronMu.Unlock()

	for _, script := range toRun {
		go runCronScript(script)
	}
}

func FireCronScript(name string) string {
	cronMu.Lock()
	var found *CronScript
	for i := range cronEntries {
		if cronEntries[i].script.Name == name {
			found = &cronEntries[i].script
			break
		}
	}
	cronMu.Unlock()
	if found == nil {
		return `{"ok":false,"error":"not found"}`
	}
	go runCronScript(*found)
	log.Warnln("[cron] manual fire: name=%q", name)
	return `{"ok":true}`
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
		matchCronDay(fields[2], t) &&
		matchCronField(fields[3], int(t.Month()), 1, 12) &&
		matchCronWeekday(fields[4], t)
}

// matchCronDay 支持高级日字段: L(月末)、L-n(倒数第n天)、nW(最近工作日)。
func matchCronDay(field string, t time.Time) bool {
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(strings.ToUpper(part))
		lastDay := time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, t.Location()).Day()
		if part == "L" {
			if t.Day() == lastDay {
				return true
			}
			continue
		}
		if strings.HasPrefix(part, "L-") {
			if offset, err := strconv.Atoi(part[2:]); err == nil && t.Day() == lastDay-offset {
				return true
			}
			continue
		}
		if strings.HasSuffix(part, "W") {
			if day, err := strconv.Atoi(part[:len(part)-1]); err == nil && t.Day() == nearestWeekday(day, t) {
				return true
			}
			continue
		}
		if matchCronPart(part, t.Day(), 1, 31) {
			return true
		}
	}
	return false
}

// matchCronWeekday 支持 "n#k"(该月第k个星期n) 与 "nL"(该月最后一个星期n)。
func matchCronWeekday(field string, t time.Time) bool {
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(strings.ToUpper(part))
		if idx := strings.IndexByte(part, '#'); idx > 0 {
			weekday, err1 := strconv.Atoi(part[:idx])
			nth, err2 := strconv.Atoi(part[idx+1:])
			if err1 == nil && err2 == nil && int(t.Weekday()) == weekday && (t.Day()-1)/7+1 == nth {
				return true
			}
			continue
		}
		if strings.HasSuffix(part, "L") && len(part) > 1 {
			if weekday, err := strconv.Atoi(part[:len(part)-1]); err == nil && int(t.Weekday()) == weekday {
				if t.Day()+7 > time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, t.Location()).Day() {
					return true
				}
			}
			continue
		}
		if matchCronPart(part, int(t.Weekday()), 0, 6) {
			return true
		}
	}
	return false
}

// nearestWeekday 返回当月最接近 day 的工作日(跳过周六周日)。
func nearestWeekday(day int, t time.Time) int {
	lastDay := time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, t.Location()).Day()
	if day > lastDay {
		day = lastDay
	}
	weekday := func(d int) time.Weekday {
		return time.Date(t.Year(), t.Month(), d, 0, 0, 0, 0, t.Location()).Weekday()
	}
	switch weekday(day) {
	case time.Saturday:
		if day+2 <= lastDay {
			return day + 2
		}
		return day - 1
	case time.Sunday:
		if day-2 >= 1 {
			return day - 2
		}
		return day + 1
	}
	return day
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
