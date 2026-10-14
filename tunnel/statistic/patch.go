package statistic

import (
	"time"
)

// rateMinWindow 速率差分窗口下限: 过短的读取间隔按此下限折算, 防抖动与除零
const rateMinWindow = 200 * time.Millisecond

type RequestNotify func(c Tracker)

var DefaultRequestNotify RequestNotify

func (m *Manager) TotalTraffic(onlyProxy bool) (up, down int64) {
	if onlyProxy {
		return m.proxyUploadTotal.Load(), m.proxyDownloadTotal.Load()
	}
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

// NowTraffic 返回当前上下行速率(字节/秒)。
// 读时差分: 速率 = (total - 基准) / elapsed, 每次读取重置基准;
// 相比固定 1s ticker 交换 blip, 消除常驻周期唤醒,
// 且各消费方(UI 2s 轮询/web UI 1s 推送/fetchTraffic)按各自节奏取平均速率, 不丢采样。
func (m *Manager) NowTraffic(onlyProxy bool) (up, down int64) {
	m.rateMu.Lock()
	defer m.rateMu.Unlock()

	now := time.Now()
	upT, downT := m.uploadTotal.Load(), m.downloadTotal.Load()
	pUpT, pDownT := m.proxyUploadTotal.Load(), m.proxyDownloadTotal.Load()

	if m.rateBaseAt.IsZero() || upT < m.rateBaseUp || downT < m.rateBaseDown ||
		pUpT < m.rateBaseProxyUp || pDownT < m.rateBaseProxyDown {
		// 首次读取或 total 被重置(ResetStatistic): 重建基准, 本轮返回 0
		m.rateBaseAt = now
		m.rateBaseUp, m.rateBaseDown = upT, downT
		m.rateBaseProxyUp, m.rateBaseProxyDown = pUpT, pDownT
		return 0, 0
	}

	elapsed := now.Sub(m.rateBaseAt)
	if elapsed < rateMinWindow {
		elapsed = rateMinWindow
	}
	nanos := elapsed.Nanoseconds()
	if nanos <= 0 {
		return 0, 0
	}

	second := int64(time.Second)
	if onlyProxy {
		up = clampNonNeg(pUpT - m.rateBaseProxyUp) * second / nanos
		down = clampNonNeg(pDownT - m.rateBaseProxyDown) * second / nanos
	} else {
		up = clampNonNeg(upT - m.rateBaseUp) * second / nanos
		down = clampNonNeg(downT - m.rateBaseDown) * second / nanos
	}

	m.rateBaseAt = now
	m.rateBaseUp, m.rateBaseDown = upT, downT
	m.rateBaseProxyUp, m.rateBaseProxyDown = pUpT, pDownT
	return up, down
}

func clampNonNeg(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}
