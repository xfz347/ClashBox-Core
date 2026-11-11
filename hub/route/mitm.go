package route

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/metacubex/mihomo/component/mitm"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

type mitmCAInfo struct {
	Enabled     bool   `json:"enabled"`
	PEM         string `json:"pem,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func mitmRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/requests", getMitmRequests)
	r.Get("/requests/detail", getMitmRequestDetail)
	r.Delete("/requests", clearMitmRequests)
	r.Get("/ca", getMitmCA)
	r.Post("/ca/regenerate", regenerateMitmCA)
	return r
}

// getMitmRequests 默认返回轻量摘要(最近 N 条, 不含 body/headers), 避免大记录集卡顿。
// query: limit=条数(默认 200, 上限 1000); full=1 返回完整记录(广告抓取分析用)。
func getMitmRequests(w http.ResponseWriter, r *http.Request) {
	mitm.TouchRecordCapture()
	query := r.URL.Query()
	if query.Get("full") == "1" {
		render.JSON(w, r, mitm.Records())
		return
	}
	limit := 200
	if raw := query.Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 1000 {
		limit = 1000
	}
	render.JSON(w, r, mitm.RecordsSummary(limit))
}

// getMitmRequestDetail 按 (time,host,path) 返回单条完整记录(点击详情时按需拉取)。
func getMitmRequestDetail(w http.ResponseWriter, r *http.Request) {
	mitm.TouchRecordCapture()
	query := r.URL.Query()
	ts, _ := strconv.ParseInt(query.Get("time"), 10, 64)
	record, ok := mitm.RecordDetail(ts, query.Get("host"), query.Get("path"))
	if !ok {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, map[string]string{"error": "record not found"})
		return
	}
	render.JSON(w, r, record)
}

func clearMitmRequests(w http.ResponseWriter, r *http.Request) {
	mitm.ClearRecords()
	render.NoContent(w, r)
}

func regenerateMitmCA(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Join(constant.Path.HomeDir(), "mitm")
	_ = os.Remove(filepath.Join(dir, "mitm-ca.crt"))
	_ = os.Remove(filepath.Join(dir, "mitm-ca.key"))
	ca, err := mitm.LoadOrCreateCA(dir)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, map[string]string{"error": err.Error()})
		return
	}
	render.JSON(w, r, mitmCAInfo{
		Enabled:     true,
		PEM:         string(ca.PEM()),
		Fingerprint: ca.Fingerprint(),
	})
}

func getMitmCA(w http.ResponseWriter, r *http.Request) {
	handler := tunnel.CurrentMITM()
	if handler == nil || handler.CA() == nil {
		render.JSON(w, r, mitmCAInfo{Enabled: false})
		return
	}
	ca := handler.CA()
	render.JSON(w, r, mitmCAInfo{
		Enabled:     handler.Enabled(),
		PEM:         string(ca.PEM()),
		Fingerprint: ca.Fingerprint(),
	})
}
