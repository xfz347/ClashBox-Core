package route

import (
	"github.com/metacubex/mihomo/component/mitm"
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
	r.Delete("/requests", clearMitmRequests)
	r.Get("/ca", getMitmCA)
	return r
}

func getMitmRequests(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, mitm.Records())
}

func clearMitmRequests(w http.ResponseWriter, r *http.Request) {
	mitm.ClearRecords()
	render.NoContent(w, r)
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
