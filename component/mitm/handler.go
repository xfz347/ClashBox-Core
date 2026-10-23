package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/itchyny/gojq"
	"github.com/metacubex/mihomo/log"
	"golang.org/x/net/http2"

	C "github.com/metacubex/mihomo/constant"
)

// DialFunc dials the target through the normal mihomo rule/outbound pipeline.
type DialFunc func(metadata *C.Metadata) (net.Conn, error)

type compiledRewrite struct {
	phase   string
	pattern string
	target  string
	flag    string
	search  string
	name    string
	value   string
}

var mitmRegexCache sync.Map

func cachedRegex(pattern string) *regexp.Regexp {
	if value, ok := mitmRegexCache.Load(pattern); ok {
		return value.(*regexp.Regexp)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	mitmRegexCache.Store(pattern, re)
	return re
}

var mitmJqCache sync.Map

func cachedJq(expr string) *gojq.Query {
	if value, ok := mitmJqCache.Load(expr); ok {
		return value.(*gojq.Query)
	}
	query, err := gojq.Parse(expr)
	if err != nil {
		query = nil
	}
	mitmJqCache.Store(expr, query)
	return query
}

// LocalResult is a locally generated response after applying request scripts/rewrites.
type LocalResult struct {
	Status  int
	Headers map[string]string
	Body    []byte
}

// ExecuteLocal runs request scripts and rewrites without dialing upstream.
func (h *Handler) ExecuteLocal(req *http.Request) *LocalResult {
	if h == nil || !h.Enabled() || req == nil || req.URL == nil {
		return nil
	}
	local := h.applyRequestScripts(req)
	if local == nil {
		local = h.applyRequestRewrites(req)
	}
	if local == nil {
		return nil
	}
	return &LocalResult{Status: local.status, Headers: local.headers, Body: local.body}
}

type localResponse struct {
	status   int
	location string
	body     []byte
	headers  map[string]string
}

type compiledLocalResponse struct {
	pattern string
	data    string
	status  int
	headers map[string]string
}

type compiledJq struct {
	phase   string
	pattern string
	expr    string
}

type compiledHTTPRule struct {
	typ     string
	pattern string
	policy  string
	re      *regexp.Regexp
}

type enginePolicyKey struct{}

func userAgentPattern(pattern string) string {
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(quoted, `\*`, `.*`)
	quoted = strings.ReplaceAll(quoted, `\?`, `.`)
	return `(?i)^` + quoted + `$`
}

// Handler intercepts TLS connections and relays decrypted HTTP traffic.
type Handler struct {
	cfg       *Config
	ca        *CA
	dial      DialFunc
	h2        *http2.Server
	maxActive int32
	active    atomic.Int32
	rewrites  []compiledRewrite
	scripts   []compiledScript
	locals    []compiledLocalResponse
	jqRules   []compiledJq
	httpRules []compiledHTTPRule
}

// New creates a MITM handler. dial must not route the connection back into
// the TUN inbound, otherwise intercepted requests will recurse.
func New(cfg *Config, ca *CA, dial DialFunc) *Handler {
	h := &Handler{
		cfg:       cfg,
		ca:        ca,
		dial:      dial,
		h2:        &http2.Server{},
		maxActive: 128,
	}
	for _, rewrite := range cfg.Rewrites {
		h.rewrites = append(h.rewrites, compiledRewrite{
			phase:   strings.ToLower(rewrite.Phase),
			pattern: rewrite.Pattern,
			target:  rewrite.Target,
			flag:    rewrite.Flag,
			search:  rewrite.Search,
			name:    rewrite.Name,
			value:   rewrite.Value,
		})
	}
	for _, script := range cfg.Scripts {
		h.scripts = append(h.scripts, compiledScript{
			phase:    strings.ToLower(script.Phase),
			pattern:  script.Pattern,
			content:  script.Content,
			argument: script.Argument,
			engine:   strings.ToLower(script.Engine),
		})
	}
	for _, local := range cfg.LocalResponses {
		headers := make(map[string]string)
		for _, item := range local.Headers {
			index := strings.IndexByte(item, ':')
			if index > 0 {
				headers[strings.TrimSpace(item[:index])] = strings.TrimSpace(item[index+1:])
			}
		}
		h.locals = append(h.locals, compiledLocalResponse{
			pattern: local.Pattern,
			data:    local.Data,
			status:  local.Status,
			headers: headers,
		})
	}
	for _, rule := range cfg.JqRules {
		h.jqRules = append(h.jqRules, compiledJq{
			phase:   strings.ToLower(rule.Phase),
			pattern: rule.Pattern,
			expr:    rule.Expr,
		})
	}
	for _, rule := range cfg.HTTPRules {
		typ := strings.ToLower(strings.TrimSpace(rule.Type))
		var re *regexp.Regexp
		var err error
		switch typ {
		case "url-regex":
			re, err = regexp.Compile(rule.Pattern)
		case "user-agent":
			re, err = regexp.Compile(userAgentPattern(rule.Pattern))
		default:
			continue
		}
		if err != nil {
			log.Warnln("[MITM] invalid HTTP rule %q: %v", rule.Pattern, err)
			continue
		}
		h.httpRules = append(h.httpRules, compiledHTTPRule{
			typ:     typ,
			pattern: rule.Pattern,
			policy:  strings.TrimSpace(rule.Policy),
			re:      re,
		})
	}
	return h
}

func (h *Handler) Enabled() bool {
	return h != nil && h.cfg != nil && h.cfg.Enable
}

// Match reports whether a connection to host should be intercepted.
func (h *Handler) Match(host string) bool {
	return h != nil && h.cfg != nil && h.cfg.Match(host)
}

// CA returns the root CA used by this handler.
func (h *Handler) CA() *CA {
	return h.ca
}

// Handle performs the server-side TLS handshake and serves the decrypted
// HTTP requests until the connection is closed.
func (h *Handler) Handle(conn net.Conn, metadata *C.Metadata) {
	if !h.Enabled() || h.ca == nil {
		return
	}
	if h.active.Add(1) > h.maxActive {
		h.active.Add(-1)
		return
	}
	defer h.active.Add(-1)

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var tlsConn *tls.Conn
	var httpConn net.Conn = conn
	if metadata.DstPort == 443 {
		tlsConn = tls.Server(conn, &tls.Config{
			GetCertificate: h.ca.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1"},
			MinVersion:     tls.VersionTLS12,
		})
		httpConn = tlsConn
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			log.Debugln("[MITM] TLS handshake for %s failed: %v", metadata.Host, err)
			_ = tlsConn.Close()
			return
		}
		_ = tlsConn.SetDeadline(time.Time{})
	} else {
		// HTTP 80: 明文转发, 不做 TLS 握手
		_ = conn.SetDeadline(time.Time{})
	}
	defer httpConn.Close()

	transport := h.newTransport(metadata)
	defer transport.CloseIdleConnections()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.serveHTTP(w, r, metadata, transport, tlsConn)
	})

	if tlsConn != nil && tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h.h2.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	_ = server.Serve(&singleConnListener{conn: httpConn})
}

func (h *Handler) newTransport(base *C.Metadata) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				host = address
				portText = "443"
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				return nil, err
			}
			meta := base.Clone()
			meta.Host = normalizeDomain(host)
			meta.DstIP = netip.Addr{}
			meta.DstPort = uint16(port)
			meta.NetWork = C.TCP
			meta.SpecialProxy = ""
			meta.SpecialRules = ""
			if policy, _ := ctx.Value(enginePolicyKey{}).(string); policy != "" {
				meta.SpecialProxy = policy
			}
			return h.dial(meta)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   4,
	}
}

func (h *Handler) matchHTTPRule(req *http.Request) *compiledHTTPRule {
	if h == nil || req == nil || req.URL == nil {
		return nil
	}
	rawURL := req.URL.String()
	agent := req.Header.Get("User-Agent")
	for i := range h.httpRules {
		rule := &h.httpRules[i]
		switch rule.typ {
		case "url-regex":
			if rule.re != nil && rule.re.MatchString(rawURL) {
				return rule
			}
		case "user-agent":
			if rule.re != nil && rule.re.MatchString(agent) {
				return rule
			}
		}
	}
	return nil
}

func (h *Handler) serveHTTP(w http.ResponseWriter, r *http.Request, base *C.Metadata, transport *http.Transport, tlsConn *tls.Conn) {
	start := time.Now()
	host := requestHost(r.Host)
	if host == "" && tlsConn != nil {
		host = normalizeDomain(tlsConn.ConnectionState().ServerName)
	}
	record := Record{
		Method:   r.Method,
		Host:     host,
		Path:     r.URL.RequestURI(),
		Proto:    r.Proto,
		ReqBytes: r.ContentLength,
	}
	if record.Path == "" {
		record.Path = r.URL.Path
	}
	if host == "sub.store" && strings.HasPrefix(record.Path, "/api/") {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
	}

	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		record.Error = "websocket is not supported by mitm"
		record.DurationMs = time.Since(start).Milliseconds()
		addRecord(record)
		http.Error(w, record.Error, http.StatusNotImplemented)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	scheme := "https"
	if base != nil && base.DstPort == 80 {
		scheme = "http"
	}
	outReq.URL.Scheme = scheme
	if outReq.URL.Host == "" {
		outReq.URL.Host = r.Host
	}
	if outReq.Host == "" {
		outReq.Host = outReq.URL.Host
	}
	if rule := h.matchHTTPRule(outReq); rule != nil {
		policy := strings.TrimSpace(rule.policy)
		upper := strings.ToUpper(policy)
		if strings.HasPrefix(upper, "REJECT") {
			record.Status = http.StatusForbidden
			record.Error = "blocked by module rule"
			record.DurationMs = time.Since(start).Milliseconds()
			addRecord(record)
			http.Error(w, "blocked by module rule", http.StatusForbidden)
			return
		}
		if policy != "" {
			outReq = outReq.WithContext(context.WithValue(outReq.Context(), enginePolicyKey{}, policy))
			outReq.Close = true
		}
	}
	removeHopByHop(outReq.Header)
	local := h.applyRequestScripts(outReq)
	if local == nil {
		local = h.applyRequestRewrites(outReq)
	}
	if local != nil {
		// Sub-Store 官方前端默认不携带后端地址，补上 api 参数，避免前端去请求已离线的 Vercel 后端
		if host == "sub.store" && local.location == "https://sub-store.vercel.app/" {
			local.location = "https://sub-store.vercel.app/?api=https://sub.store"
		}
		for key, value := range local.headers {
			w.Header().Set(key, value)
		}
		if local.location != "" {
			w.Header().Set("Location", local.location)
		}
		w.WriteHeader(local.status)
		if len(local.body) > 0 {
			_, _ = w.Write(local.body)
		}
		record.Status = local.status
		record.Location = local.location
		record.RespHeaders = local.headers
		if len(local.body) > 0 && len(local.body) <= 16384 {
			record.RespPreview = string(local.body)
		}
		if record.Location == "" {
			record.Location = local.headers["Location"]
		}
		if record.Location == "" {
			record.Location = local.headers["location"]
		}
		record.RespBytes = int64(len(local.body))
		record.DurationMs = time.Since(start).Milliseconds()
		addRecord(record)
		return
	}

	resp, err := transport.RoundTrip(outReq)
	if err == nil && resp != nil {
		if host == "sub.store" && resp.Header.Get("Location") == "https://sub-store.vercel.app/" {
			resp.Header.Set("Location", "https://sub-store.vercel.app/?api=https://sub.store")
		}
		record.Location = resp.Header.Get("Location")
	}
	if err != nil {
		record.Error = err.Error()
		record.DurationMs = time.Since(start).Milliseconds()
		addRecord(record)
		http.Error(w, "mitm upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	h.applyResponseScripts(resp)
	h.applyResponseRewrites(resp)
	removeHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	written, copyErr := io.Copy(w, resp.Body)

	record.Status = resp.StatusCode
	record.RespBytes = written
	record.DurationMs = time.Since(start).Milliseconds()
	if copyErr != nil {
		record.Error = copyErr.Error()
	}
	addRecord(record)
}

func (h *Handler) bodyLimit() int64 {
	if h.cfg != nil && h.cfg.MaxBodySize > 0 {
		return int64(h.cfg.MaxBodySize)
	}
	return 1 << 20
}

func (h *Handler) applyRequestScripts(req *http.Request) *localResponse {
	for _, script := range h.scripts {
		if script.phase != "http-request" {
			continue
		}
		re := cachedRegex(script.pattern)
		if re == nil || !re.MatchString(req.URL.String()) {
			continue
		}
		var body []byte
		if req.Body != nil {
			limit := h.bodyLimit()
			data, err := io.ReadAll(io.LimitReader(req.Body, limit+1))
			if err != nil {
				continue
			}
			if int64(len(data)) > limit {
				req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), req.Body))
				continue
			}
			body = data
			req.Body = io.NopCloser(bytes.NewReader(data))
		}
		result, err := runScript(script, req, nil, body)
		if err != nil {
			log.Debugln("[MITM] request script %s failed: %v", script.pattern, err)
			continue
		}
		if result.statusSet || (result.bodySet && result.url == "" && result.method == "") {
			status := result.status
			if status <= 0 {
				status = http.StatusOK
			}
			location := ""
			if status >= 300 && status < 400 {
				location = result.url
			}
			return &localResponse{status: status, location: location, body: result.body, headers: result.headers}
		}
		applyScriptRequest(result, req)
	}
	return nil
}

func (h *Handler) applyResponseScripts(resp *http.Response) {
	requestURL := ""
	if resp.Request != nil {
		requestURL = resp.Request.URL.String()
	}
	if requestURL == "" {
		return
	}
	for _, script := range h.scripts {
		if script.phase != "http-response" {
			continue
		}
		re := cachedRegex(script.pattern)
		if re == nil || !re.MatchString(requestURL) {
			continue
		}
		limit := h.bodyLimit()
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			continue
		}
		if int64(len(data)) > limit {
			resp.Body = struct {
				io.Reader
				io.Closer
			}{Reader: io.MultiReader(bytes.NewReader(data), resp.Body), Closer: resp.Body}
			continue
		}
		original := resp.Body
		resp.Body = struct {
			io.Reader
			io.Closer
		}{Reader: bytes.NewReader(data), Closer: original}
		result, err := runScript(script, resp.Request, resp, data)
		if err != nil {
			log.Debugln("[MITM] response script %s failed: %v", script.pattern, err)
			continue
		}
		applyScriptResponse(result, resp)
	}
}

func (h *Handler) applyRequestRewrites(req *http.Request) *localResponse {
	for _, local := range h.locals {
		re := cachedRegex(local.pattern)
		if re == nil || !re.MatchString(req.URL.String()) {
			continue
		}
		status := local.status
		if status <= 0 {
			status = http.StatusOK
		}
		return &localResponse{status: status, body: []byte(local.data), headers: local.headers}
	}
	hasBody := false
	for _, rewrite := range h.rewrites {
		switch rewrite.phase {
		case "url":
			full := req.URL.String()
			re := cachedRegex(rewrite.pattern)
			if re != nil && re.MatchString(full) {
				replaced := re.ReplaceAllString(full, rewrite.target)
				if parsed, err := url.Parse(replaced); err == nil {
					req.URL = parsed
					req.Host = parsed.Host
				}
			}
		case "header":
			if rewrite.pattern == "" || rewriteMatches(rewrite.pattern, req.URL.String()) {
				applyHeaderAction(req.Header, rewrite.target)
			}
		case "request-header":
			if rewriteMatches(rewrite.pattern, req.URL.String()) {
				applyHeaderRule(req.Header, rewrite)
			}
		case "request-body":
			if rewriteMatches(rewrite.pattern, req.URL.String()) {
				applyRequestBody(req, rewrite)
			}
		case "body":
			hasBody = true
		case "reject":
			re := cachedRegex(rewrite.pattern)
			if re != nil && re.MatchString(req.URL.String()) {
				return &localResponse{status: http.StatusForbidden, body: []byte("Blocked by module")}
			}
		case "redirect":
			re := cachedRegex(rewrite.pattern)
			if re != nil && re.MatchString(req.URL.String()) {
				status := http.StatusFound
				if rewrite.flag == "307" {
					status = http.StatusTemporaryRedirect
				}
				return &localResponse{status: status, location: rewrite.target}
			}
		}
	}
	h.applyRequestJq(req)
	if hasBody {
		// 保证响应体可被正则处理(避免 gzip 压缩体)
		req.Header.Set("Accept-Encoding", "identity")
	}
	return nil
}

func (h *Handler) applyRequestJq(req *http.Request) {
	if h == nil || req == nil || req.URL == nil || len(h.jqRules) == 0 {
		return
	}
	requestURL := req.URL.String()
	matched := false
	for _, rule := range h.jqRules {
		if rule.phase == "http-request-jq" && rewriteMatches(rule.pattern, requestURL) {
			matched = true
			break
		}
	}
	if !matched || req.Body == nil {
		return
	}
	data, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return
	}
	data = h.applyJqRewrites(data, requestURL, "http-request-jq")
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.ContentLength = int64(len(data))
}

func (h *Handler) applyResponseRewrites(resp *http.Response) {
	hasBody := false
	for _, rewrite := range h.rewrites {
		switch rewrite.phase {
		case "header":
			if rewrite.pattern == "" || rewriteMatches(rewrite.pattern, requestURLOf(resp)) {
				applyHeaderAction(resp.Header, rewrite.target)
			}
		case "response-header":
			if rewriteMatches(rewrite.pattern, requestURLOf(resp)) {
				applyHeaderRule(resp.Header, rewrite)
			}
		case "body":
			hasBody = true
		case "response-body":
			hasBody = true
		}
	}
	requestURL := ""
	if resp.Request != nil {
		requestURL = resp.Request.URL.String()
	}
	hasJq := false
	if requestURL != "" {
		for _, rule := range h.jqRules {
			if rule.phase == "http-response-jq" {
				re := cachedRegex(rule.pattern)
				if re != nil && re.MatchString(requestURL) {
					hasJq = true
					break
				}
			}
		}
	}
	if !hasBody && !hasJq {
		return
	}
	limit := int64(h.cfg.MaxBodySize)
	if limit <= 0 {
		limit = 1 << 20
	}
	if resp.ContentLength > limit {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return
	}
	if hasJq {
		data = h.applyJqRewrites(data, requestURL, "http-response-jq")
	}
	for _, rewrite := range h.rewrites {
		if rewrite.phase == "response-body" {
			if requestURL != "" && rewriteMatches(rewrite.pattern, requestURL) && rewrite.search != "" {
				if re := cachedRegex(rewrite.search); re != nil {
					data = re.ReplaceAll(data, []byte(rewrite.target))
				}
			}
			continue
		}
		if rewrite.phase != "body" {
			continue
		}
		re := cachedRegex(rewrite.pattern)
		if re != nil {
			data = re.ReplaceAll(data, []byte(rewrite.target))
		}
	}
	original := resp.Body
	resp.Body = struct {
		io.Reader
		io.Closer
	}{Reader: bytes.NewReader(data), Closer: original}
	resp.ContentLength = int64(len(data))
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
}

func (h *Handler) applyJqRewrites(data []byte, requestURL string, phase string) []byte {
	var input interface{}
	if err := json.Unmarshal(data, &input); err != nil {
		return data
	}
	current := input
	for _, rule := range h.jqRules {
		if rule.phase != phase {
			continue
		}
		re := cachedRegex(rule.pattern)
		if re == nil || !re.MatchString(requestURL) {
			continue
		}
		query := cachedJq(rule.expr)
		if query == nil {
			continue
		}
		iter := query.Run(current)
		result, ok := iter.Next()
		if !ok {
			continue
		}
		if err, isError := result.(error); isError {
			log.Debugln("[MITM] jq %q failed: %v", rule.phase, err)
			continue
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			continue
		}
		var next interface{}
		if err := json.Unmarshal(encoded, &next); err != nil {
			continue
		}
		current = next
		data = encoded
	}
	return data
}

func applyHeaderAction(header http.Header, target string) {
	index := strings.IndexByte(target, ' ')
	if index <= 0 {
		return
	}
	action := strings.ToLower(strings.TrimSpace(target[:index]))
	rest := strings.TrimSpace(target[index+1:])
	switch action {
	case "header-add":
		name, value := splitHeader(rest)
		if name != "" {
			header.Add(name, value)
		}
	case "header-del", "header-delete", "header-remove":
		header.Del(rest)
	case "header-replace":
		name, value := splitHeader(rest)
		if name != "" {
			header.Set(name, value)
		}
	}
}

func rewriteMatches(pattern string, value string) bool {
	if strings.TrimSpace(pattern) == "" {
		return true
	}
	re := cachedRegex(pattern)
	return re != nil && re.MatchString(value)
}

func requestURLOf(resp *http.Response) string {
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.String()
	}
	return ""
}

func applyHeaderRule(header http.Header, rule compiledRewrite) {
	name := strings.TrimSpace(rule.name)
	if name == "" {
		return
	}
	switch strings.ToLower(strings.TrimSpace(rule.target)) {
	case "add", "header-add":
		header.Add(name, rule.value)
	case "del", "delete", "remove", "header-del":
		header.Del(name)
	default:
		header.Set(name, rule.value)
	}
}

func applyRequestBody(req *http.Request, rule compiledRewrite) {
	if req == nil || req.Body == nil || strings.TrimSpace(rule.search) == "" {
		return
	}
	data, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return
	}
	re := cachedRegex(rule.search)
	if re == nil {
		return
	}
	data = re.ReplaceAll(data, []byte(rule.target))
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.ContentLength = int64(len(data))
}

func splitHeader(text string) (string, string) {
	index := strings.IndexByte(text, ':')
	if index <= 0 {
		return strings.TrimSpace(text), ""
	}
	return strings.TrimSpace(text[:index]), strings.TrimSpace(text[index+1:])
}

func requestHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return normalizeDomain(h)
	}
	return normalizeDomain(strings.Trim(host, "[]"))
}

func removeHopByHop(header http.Header) {
	for _, key := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(key)
	}
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, fmt.Errorf("listener closed")
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
