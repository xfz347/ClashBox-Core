package statistic

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
)

// snapshotCacheTTL 快照缓存时间窗: 同窗口内重复请求(连接页/代理页/web UI)直接复用,
// 避免每次全量遍历 tracker 构造连接列表造成 CPU 尖峰
const snapshotCacheTTL = 500 * time.Millisecond

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		pid:           int32(os.Getpid()),
	}
	DefaultManager.lastTrafficAt.Store(time.Now().Unix())
}

type Manager struct {
	connections        xsync.Map[string, Tracker]
	smartTarget        xsync.Map[string, *xsync.Map[string, bool]]
	uploadTotal        atomic.Int64
	downloadTotal      atomic.Int64
	proxyUploadTotal   atomic.Int64
	proxyDownloadTotal atomic.Int64
	lastTrafficAt      atomic.Int64 // 最近一次流量打点(unix 秒), 供空闲降频判断
	pid                int32
	memory             uint64

	rateMu            sync.Mutex
	rateBaseAt        time.Time // 速率差分基准时间
	rateBaseUp        int64     // 基准 uploadTotal
	rateBaseDown      int64
	rateBaseProxyUp   int64
	rateBaseProxyDown int64

	snapshotMu    sync.Mutex
	snapshotCache *Snapshot
	snapshotAt    time.Time
}

func (m *Manager) Join(c Tracker) {
	if DefaultRequestNotify != nil {
		DefaultRequestNotify(c)
	}
	m.connections.Store(c.ID(), c)
	m.joinSmartTarget(c)
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
	m.leaveSmartTarget(c)
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

func (m *Manager) PushUploaded(lastChain string, size int64) {
	if lastChain != "DIRECT" {
		m.proxyUploadTotal.Add(size)
	}
	m.uploadTotal.Add(size)
	m.lastTrafficAt.Store(time.Now().Unix())
}

func (m *Manager) PushDownloaded(lastChain string, size int64) {
	if lastChain != "DIRECT" {
		m.proxyDownloadTotal.Add(size)
	}
	m.downloadTotal.Add(size)
	m.lastTrafficAt.Store(time.Now().Unix())
}

// LastTrafficAt 返回最近一次流量打点时间, 用于空闲判断
func (m *Manager) LastTrafficAt() time.Time {
	sec := m.lastTrafficAt.Load()
	if sec <= 0 {
		return time.Now()
	}
	return time.Unix(sec, 0)
}

// Now 返回当前上下行速率(字节/秒)。读时差分计算, 见 NowTraffic
func (m *Manager) Now() (up int64, down int64) {
	return m.NowTraffic(false)
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory
}

func (m *Manager) Snapshot() *Snapshot {
	m.snapshotMu.Lock()
	defer m.snapshotMu.Unlock()
	if m.snapshotCache != nil && time.Since(m.snapshotAt) < snapshotCacheTTL {
		return m.snapshotCache
	}
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	snapshot := &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory,
	}
	m.snapshotCache = snapshot
	m.snapshotAt = time.Now()
	return snapshot
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory = stat.RSS
}

func (m *Manager) ResetStatistic() {
	m.uploadTotal.Store(0)
	m.downloadTotal.Store(0)
	m.proxyUploadTotal.Store(0)
	m.proxyDownloadTotal.Store(0)

	m.rateMu.Lock()
	m.rateBaseAt = time.Now()
	m.rateBaseUp, m.rateBaseDown = 0, 0
	m.rateBaseProxyUp, m.rateBaseProxyDown = 0, 0
	m.rateMu.Unlock()

	m.snapshotMu.Lock()
	m.snapshotCache = nil
	m.snapshotMu.Unlock()
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}

func (m *Manager) joinSmartTarget(c Tracker) {
	info := c.Info()
	target := info.Metadata.SmartTarget

	if target == "" {
		return
	}

	id := c.ID()

	result, _ := m.smartTarget.LoadOrStoreFn(target, func() *xsync.Map[string, bool] {
		return xsync.NewMap[string, bool]()
	})
	result.Store(id, true)
}

func (m *Manager) leaveSmartTarget(c Tracker) {
	info := c.Info()
	target := info.Metadata.SmartTarget

	if target == "" {
		return
	}

	id := c.ID()

	m.smartTarget.Compute(target, func(result *xsync.Map[string, bool], loaded bool) (*xsync.Map[string, bool], xsync.ComputeOp) {
		if loaded {
			result.Delete(id)
			if result.IsEmpty() {
				return result, xsync.DeleteOp
			}
			return result, xsync.UpdateOp
		}
		return result, xsync.CancelOp
	})
}

func (m *Manager) RangeSmartTarget(target string, fn func(id string) bool) {
	if result, ok := m.smartTarget.Load(target); ok {
		result.Range(func(id string, _ bool) bool {
			return fn(id)
		})
	}
}
