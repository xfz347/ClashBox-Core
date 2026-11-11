package mitm

import (
	"sync"
	"sync/atomic"
	"time"
)

// Record is a single intercepted HTTP transaction (metadata only by default).
type Record struct {
	Time       int64  `json:"time"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Proto      string `json:"proto"`
	Status     int    `json:"status"`
	DurationMs int64  `json:"durationMs"`
	ReqBytes   int64  `json:"reqBytes"`
	RespBytes  int64  `json:"respBytes"`
	Location   string            `json:"location"`
	ReqHeaders map[string]string `json:"reqHeaders,omitempty"`
	ReqBody    string            `json:"reqBody,omitempty"`
	RespHeaders map[string]string `json:"respHeaders,omitempty"`
	RespPreview string            `json:"respPreview,omitempty"`
	Error      string `json:"error"`
}

// 元数据保留条数(列表展示用)。
const recordLimit = 400
// 仅最近 N 条保留 body/headers 等大字段, 其余清空。
// MITM 长时间开启时, 1000 条 × (8KB 请求体 + 8KB 响应预览 + headers) 会长期占用 20MB+。
const recordHeavyLimit = 100

// Ring buffer: 避免每次请求都 copy 整个切片(O(n)), 高频 MITM 下可明显降低 CPU/发热。
var recordStore = struct {
	sync.RWMutex
	items []Record
	start int
	count int
}{items: make([]Record, recordLimit)}

func addRecord(record Record) {
	record.Time = time.Now().UnixMilli()
	recordStore.Lock()
	defer recordStore.Unlock()

	if recordStore.count < recordLimit {
		idx := (recordStore.start + recordStore.count) % recordLimit
		recordStore.items[idx] = record
		recordStore.count++
	} else {
		// 覆盖最旧的一条并前移 start
		recordStore.items[recordStore.start] = record
		recordStore.start = (recordStore.start + 1) % recordLimit
	}

	// 只保留最近 recordHeavyLimit 条的大字段
	if recordStore.count > recordHeavyLimit {
		oldIdx := (recordStore.start + recordStore.count - recordHeavyLimit - 1 + recordLimit) % recordLimit
		recordStore.items[oldIdx].ReqBody = ""
		recordStore.items[oldIdx].RespPreview = ""
		recordStore.items[oldIdx].ReqHeaders = nil
		recordStore.items[oldIdx].RespHeaders = nil
	}
}

// Records returns a copy of the recent intercepted transactions (oldest -> newest).
func Records() []Record {
	recordStore.RLock()
	defer recordStore.RUnlock()
	out := make([]Record, recordStore.count)
	for i := 0; i < recordStore.count; i++ {
		out[i] = recordStore.items[(recordStore.start+i)%recordLimit]
	}
	return out
}

// RecordsSummary 返回最近 limit 条记录, 并剥离体积大的字段(请求/响应体与头),
// 供拦截记录列表页使用——避免一次把数 MB 的 body 全量传给 UI 造成卡顿。
func RecordsSummary(limit int) []Record {
	recordStore.RLock()
	defer recordStore.RUnlock()
	total := recordStore.count
	if limit <= 0 || limit > total {
		limit = total
	}
	out := make([]Record, limit)
	for i := 0; i < limit; i++ {
		src := recordStore.items[(recordStore.start+total-limit+i)%recordLimit]
		src.ReqBody = ""
		src.RespPreview = ""
		src.ReqHeaders = nil
		src.RespHeaders = nil
		out[i] = src
	}
	return out
}

// RecordDetail 按 (time, host, path) 查找一条完整记录(含 body/headers)。
func RecordDetail(ts int64, host, path string) (Record, bool) {
	recordStore.RLock()
	defer recordStore.RUnlock()
	for i := recordStore.count - 1; i >= 0; i-- {
		item := recordStore.items[(recordStore.start+i)%recordLimit]
		if item.Time == ts && item.Host == host && item.Path == path {
			return item, true
		}
	}
	return Record{}, false
}

// ClearRecords drops all buffered transactions.
func ClearRecords() {
	recordStore.Lock()
	defer recordStore.Unlock()
	recordStore.items = make([]Record, recordLimit)
	recordStore.start = 0
	recordStore.count = 0
}

// 记录详情采集窗口: 默认不采集 header/body(省电), 拦截记录页/AdProbe 访问时开启一段窗口。
var recordDetailUntil atomic.Int64

// TouchRecordCapture 开启/续期记录详情采集(默认 5 分钟)。
func TouchRecordCapture() {
	recordDetailUntil.Store(time.Now().Add(5 * time.Minute).UnixMilli())
}

func recordCaptureActive() bool {
	until := recordDetailUntil.Load()
	return until > 0 && time.Now().UnixMilli() < until
}
