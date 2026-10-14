package tunnel

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// 并发连接/拨号准入门控: 极端场景(连接风暴/恶意扫描)下封顶内存峰值。
// 超限时拒绝新会话, 已建立会话不受影响。
const (
	tcpConnAdmitLimit = 1024
	udpDialAdmitLimit = 256
)

var (
	tcpConnCount atomic.Int64
	udpDialCount atomic.Int64
)

func admitTCPConn() bool {
	if n := tcpConnCount.Add(1); n > tcpConnAdmitLimit {
		tcpConnCount.Add(-1)
		return false
	}
	return true
}

func releaseTCPConn() {
	tcpConnCount.Add(-1)
}

func admitUDPDial() bool {
	if n := udpDialCount.Add(1); n > udpDialAdmitLimit {
		udpDialCount.Add(-1)
		return false
	}
	return true
}

func releaseUDPDial() {
	udpDialCount.Add(-1)
}

// sessionPacer 新会话节奏器(令牌桶): 内存压力期限制新会话建立速率,
// 只延迟不拒绝(单会话最长等待 shedPaceMaxWait), 压力解除立即放行。
const (
	shedPaceRate    = 8
	shedPaceBurst   = 8
	shedPaceMaxWait = 5 * time.Second
)

type sessionPacer struct {
	active atomic.Bool

	mu       sync.Mutex
	released chan struct{}
	tat      time.Time
}

var globalSessionPacer = newSessionPacer()

func newSessionPacer() *sessionPacer {
	return &sessionPacer{released: make(chan struct{})}
}

func (p *sessionPacer) setActive(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active.Load() == on {
		return
	}
	p.active.Store(on)
	if on {
		p.tat = time.Time{}
		return
	}
	close(p.released)
	p.released = make(chan struct{})
}

func (p *sessionPacer) wait(ctx context.Context, network C.NetWork) {
	if !p.active.Load() {
		return
	}
	p.mu.Lock()
	if !p.active.Load() {
		p.mu.Unlock()
		return
	}
	now := time.Now()
	tat := p.tat
	if tat.Before(now) {
		tat = now
	}
	interval := time.Second / shedPaceRate
	depart := tat.Add(-time.Duration(shedPaceBurst-1) * interval)
	delay := depart.Sub(now)
	capped := delay > shedPaceMaxWait
	if capped {
		delay = shedPaceMaxWait
	} else {
		p.tat = tat.Add(interval)
	}
	released := p.released
	p.mu.Unlock()

	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	start := time.Now()
	select {
	case <-timer.C:
	case <-released:
	case <-ctx.Done():
	}
	if waited := time.Since(start); waited >= time.Second {
		log.Debugln("[Memory] paced a new %s session for %s", network, waited.Round(time.Millisecond))
	}
}

// SetSessionPacerActive 内存压力联动入口: armed 及以上开启节奏限制
func SetSessionPacerActive(on bool) {
	globalSessionPacer.setActive(on)
}
