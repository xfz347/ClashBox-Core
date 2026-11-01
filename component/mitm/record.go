package mitm

import (
	"sync"
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

const recordLimit = 1000

var recordStore = struct {
	sync.RWMutex
	items []Record
}{items: make([]Record, 0, recordLimit)}

func addRecord(record Record) {
	record.Time = time.Now().UnixMilli()
	recordStore.Lock()
	defer recordStore.Unlock()
	if len(recordStore.items) >= recordLimit {
		copy(recordStore.items, recordStore.items[1:])
		recordStore.items = recordStore.items[:len(recordStore.items)-1]
	}
	recordStore.items = append(recordStore.items, record)
}

// Records returns a copy of the recent intercepted transactions.
func Records() []Record {
	recordStore.RLock()
	defer recordStore.RUnlock()
	out := make([]Record, len(recordStore.items))
	copy(out, recordStore.items)
	return out
}


// RecordsSummary 返回最近 limit 条记录, 并剥离体积大的字段(请求/响应体与头),
// 供拦截记录列表页使用——避免一次把数 MB 的 body 全量传给 UI 造成卡顿。
func RecordsSummary(limit int) []Record {
	recordStore.RLock()
	defer recordStore.RUnlock()
	total := len(recordStore.items)
	if limit <= 0 || limit > total {
		limit = total
	}
	out := make([]Record, limit)
	for i := 0; i < limit; i++ {
		src := recordStore.items[total-limit+i]
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
	for i := len(recordStore.items) - 1; i >= 0; i-- {
		item := recordStore.items[i]
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
	recordStore.items = recordStore.items[:0]
}
