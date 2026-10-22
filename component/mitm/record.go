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

// ClearRecords drops all buffered transactions.
func ClearRecords() {
	recordStore.Lock()
	defer recordStore.Unlock()
	recordStore.items = recordStore.items[:0]
}
