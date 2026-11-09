package route

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

var (
	SwitchProxiesCallback func(sGroup string, sProxy string)
)

const (
	delayCacheSuccessTTL = 5 * time.Second
	delayCacheFailTTL    = 3 * time.Second
)

type delayCacheEntry struct {
	ts      time.Time
	delay   uint16
	failed  bool
	timeout bool
}

// delayCache 单节点测速节流: key = 节点名+"\n"+测试URL。
// 连点同一节点测速会向同一 IP:port 高频建连, 蜂窝网络对此触发限速
// (SYN 丢弃/ClientHello 黑洞), 表现为超时或几千 ms。TTL 内直接回放上次
// 结果, 不发起新连接; 组测速走 proxy.URLTest 直调, 不受影响保持并发。
var delayCache sync.Map

func proxyRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies)

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName)
		r.Get("/", getProxy)
		r.Get("/delay", getProxyDelay)
		r.Put("/", updateProxy)
		r.Delete("/", unfixedProxy)
	})
	return r
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProxyName).(string)
		proxies := tunnel.Proxies()
		proxy, exist := proxies[name]
		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getProxies(w http.ResponseWriter, r *http.Request) {
	proxies := tunnel.Proxies()
	render.JSON(w, r, render.M{
		"proxies": proxies,
	})
}

func getProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	render.JSON(w, r, proxy)
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Name string `json:"name"`
	}{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector"))
		return
	}

	if err := selector.Set(req.Name); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(fmt.Sprintf("Selector update error: %s", err.Error())))
		return
	}

	cachefile.Cache().SetSelected(proxy.Name(), req.Name)
	if SwitchProxiesCallback != nil {
		// refresh tray menu
		go SwitchProxiesCallback(proxy.Name(), req.Name)
	}
	render.NoContent(w, r)
}

func getProxyDelay(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	url := query.Get("url")
	timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](query.Get("expected"))
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)

	cacheKey := proxy.Name() + "\n" + url
	if v, ok := delayCache.Load(cacheKey); ok {
		if entry, ok := v.(delayCacheEntry); ok {
			ttl := delayCacheSuccessTTL
			if entry.failed {
				ttl = delayCacheFailTTL
			}
			if time.Since(entry.ts) < ttl {
				writeDelayCached(w, r, entry)
				return
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(timeout))
	defer cancel()

	delay, err := proxy.URLTest(ctx, url, expectedStatus)
	if ctx.Err() != nil {
		delayCache.Store(cacheKey, delayCacheEntry{ts: time.Now(), failed: true, timeout: true})
		render.Status(r, http.StatusGatewayTimeout)
		render.JSON(w, r, ErrRequestTimeout)
		return
	}

	if err != nil || delay == 0 {
		delayCache.Store(cacheKey, delayCacheEntry{ts: time.Now(), failed: true})
		render.Status(r, http.StatusServiceUnavailable)
		if err != nil && delay != 0 {
			render.JSON(w, r, err)
		} else {
			render.JSON(w, r, newError("An error occurred in the delay test"))
		}
		return
	}

	delayCache.Store(cacheKey, delayCacheEntry{ts: time.Now(), delay: delay})
	render.JSON(w, r, render.M{
		"delay": delay,
	})
}

func writeDelayCached(w http.ResponseWriter, r *http.Request, entry delayCacheEntry) {
	if entry.failed {
		if entry.timeout {
			render.Status(r, http.StatusGatewayTimeout)
			render.JSON(w, r, ErrRequestTimeout)
			return
		}
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError("An error occurred in the delay test"))
		return
	}
	render.JSON(w, r, render.M{
		"delay": entry.delay,
	})
}

func unfixedProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	if selectAble, ok := proxy.Adapter().(outboundgroup.SelectAble); ok && proxy.Type() != C.Selector {
		selectAble.ForceSet("")
		cachefile.Cache().SetSelected(proxy.Name(), "")
		render.NoContent(w, r)
		return
	}
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, ErrBadRequest)
}
