package mitm

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/metacubex/mihomo/log"
)

type compiledScript struct {
	phase    string
	pattern  string
	content  string
	argument string
	engine   string
}

type scriptResult struct {
	done       bool
	url        string
	method     string
	headers    map[string]string
	body       []byte
	bodySet    bool
	status     int
	statusSet  bool
}

var scriptStore sync.Map

// ExternalScriptResult is the result returned by an embedded WebView script host.
type ExternalScriptResult struct {
	Status    int
	StatusSet bool
	Headers   map[string]string
	Body      []byte
	BodySet   bool
}

// ExternalScriptExecutor runs a script outside the Go process (embedded WebView).
type ExternalScriptExecutorFunc func(script Script, request *http.Request, response *http.Response, body []byte) (*ExternalScriptResult, error)

var ExternalScriptExecutor ExternalScriptExecutorFunc

// runScript executes one Surge-style script with the supported global API:
// $request, $response, $done, $persistentStore and console.log.
func runScript(script compiledScript, request *http.Request, response *http.Response, body []byte) (result *scriptResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("script panic: %v", recovered)
		}
	}()
	if ExternalScriptExecutor == nil {
		return nil, fmt.Errorf("external script executor is not initialized")
	}
	{
		external, err := ExternalScriptExecutor(Script{
			Phase:    script.phase,
			Pattern:  script.pattern,
			Content:  script.content,
			Argument: script.argument,
			Engine:   script.engine,
		}, request, response, body)
		if err == nil && external != nil {
			return &scriptResult{
				done:      true,
				status:    external.Status,
				statusSet: external.StatusSet,
				headers:   external.Headers,
				body:      external.Body,
				bodySet:   external.BodySet,
			}, nil
		}
		log.Warnln("[MITM] QuickJS script failed: %v", err)
		if err == nil {
			err = fmt.Errorf("external script executor returned nil")
		}
		return nil, err
	}
	vm := goja.New()
	_, _ = vm.RunString(`
if (typeof URL === "undefined") {
  var URL = function(input) {
    this.href = String(input);
    var m = this.href.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^\/?#]*)([^?#]*)(\?[^#]*)?/);
    this.pathname = m ? (m[2] || "/") : this.href;
    var query = (m && m[3]) ? m[3].substring(1) : "";
    var params = {};
    if (query) {
      query.split("&").forEach(function(pair) {
        var i = pair.indexOf("=");
        var k = decodeURIComponent(i < 0 ? pair : pair.substring(0, i));
        var v = decodeURIComponent(i < 0 ? "" : pair.substring(i + 1));
        params[k] = v;
      });
    }
    this.searchParams = { get: function(key) { return params[key] === undefined ? null : params[key]; } };
  };
}
`)
	result = &scriptResult{}

	vm.Set("$done", func(call goja.FunctionCall) goja.Value {
		result.done = true
		if len(call.Arguments) > 0 {
			readDoneValue(call.Argument(0), result)
		}
		return goja.Undefined()
	})
	vm.Set("$persistentStore", map[string]interface{}{
		"read": func(key string) string {
			if value, ok := scriptStore.Load(key); ok {
				return value.(string)
			}
			return ""
		},
		"write": func(key string, value string) bool {
			scriptStore.Store(key, value)
			return true
		},
	})
	vm.Set("console", map[string]interface{}{
		"log": func(args ...interface{}) {
			log.Debugln("[MITM][script] %v", args)
		},
	})
	vm.Set("$environment", map[string]string{
		"language": "zh-CN",
	})
	vm.Set("$argument", script.argument)
	vm.Set("$script", map[string]interface{}{
		"name":      "mihomo-mitm",
		"startTime": time.Now(),
	})
	vm.Set("$notification", map[string]interface{}{
		"post": func(call goja.FunctionCall) goja.Value {
			return goja.Undefined()
		},
	})
	vm.Set("atob", func(value string) string {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return ""
		}
		return string(decoded)
	})
	vm.Set("btoa", func(value string) string {
		return base64.StdEncoding.EncodeToString([]byte(value))
	})

	doHttp := func(defaultMethod string, args []goja.Value) goja.Value {
		var callback goja.Callable
		if len(args) > 0 {
			if fn, ok := goja.AssertFunction(args[len(args)-1]); ok {
				callback = fn
				args = args[:len(args)-1]
			}
		}
		if len(args) == 0 {
			return goja.Undefined()
		}
		method := defaultMethod
		target := ""
		headers := make(map[string]string)
		timeout := 5 * time.Second
		var reader io.Reader
		if object, ok := args[0].Export().(map[string]interface{}); ok {
			target = fmt.Sprint(object["url"])
			if writtenMethod, ok := object["method"].(string); ok && writtenMethod != "" {
				method = strings.ToUpper(writtenMethod)
			}
			switch headerValues := object["headers"].(type) {
			case map[string]interface{}:
				for key, value := range headerValues {
					headers[key] = fmt.Sprint(value)
				}
			case map[string]string:
				for key, value := range headerValues {
					headers[key] = value
				}
			}
			if value, ok := object["body"]; ok && value != nil {
				switch bodyValue := value.(type) {
				case []byte:
					reader = bytes.NewReader(bodyValue)
				case string:
					reader = strings.NewReader(bodyValue)
				default:
					reader = strings.NewReader(fmt.Sprint(bodyValue))
				}
			}
			if value, ok := object["timeout"].(float64); ok && value > 0 {
				timeout = time.Duration(value * float64(time.Second))
			}
		} else {
			target = args[0].String()
			if method != http.MethodGet && len(args) > 1 {
				reader = strings.NewReader(args[len(args)-1].String())
			}
		}
		req, err := http.NewRequest(method, target, reader)
		if err != nil {
			if callback != nil {
				_, _ = callback(goja.Undefined(), vm.ToValue(err.Error()), goja.Null(), goja.Null())
			}
			return goja.Undefined()
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			if callback != nil {
				_, _ = callback(goja.Undefined(), vm.ToValue(err.Error()), goja.Null(), goja.Null())
			}
			return goja.Undefined()
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		responseHeaders := make(map[string]string)
		for key, values := range resp.Header {
			if len(values) > 0 {
				responseHeaders[key] = strings.Join(values, ",")
			}
		}
		if callback != nil {
			_, _ = callback(goja.Undefined(), goja.Null(), vm.ToValue(map[string]interface{}{
				"status":     resp.StatusCode,
				"statusCode": resp.StatusCode,
				"headers":    responseHeaders,
				"body":       string(data),
				"bodyBytes":  data,
			}), vm.ToValue(string(data)))
		}
		return goja.Undefined()
	}
	vm.Set("$httpClient", map[string]interface{}{
		"get": func(call goja.FunctionCall) goja.Value {
			return doHttp(http.MethodGet, call.Arguments)
		},
		"post": func(call goja.FunctionCall) goja.Value {
			return doHttp(http.MethodPost, call.Arguments)
		},
		"put": func(call goja.FunctionCall) goja.Value {
			return doHttp(http.MethodPut, call.Arguments)
		},
		"delete": func(call goja.FunctionCall) goja.Value {
			return doHttp(http.MethodDelete, call.Arguments)
		},
	})

	if request != nil {
		vm.Set("$request", map[string]interface{}{
			"url":     request.URL.String(),
			"method":  request.Method,
			"headers": headerMap(request.Header),
			"body":    string(body),
		})
	}
	if response != nil {
		vm.Set("$response", map[string]interface{}{
			"status":  response.StatusCode,
			"headers": headerMap(response.Header),
			"body":    string(body),
		})
	}

	done := make(chan error, 1)
	go func() {
		_, err := vm.RunString(script.content)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return nil, err
		}
	case <-time.After(5 * time.Second):
		vm.Interrupt("script timeout")
		return nil, fmt.Errorf("script timeout")
	}
	if !result.done {
		return result, nil
	}
	return result, nil
}

func readDoneValue(value goja.Value, result *scriptResult) {
	exported := value.Export()
	obj, ok := exported.(map[string]interface{})
	if !ok {
		return
	}
	readDoneMap(obj, result)
	if inner, ok := obj["response"].(map[string]interface{}); ok {
		readDoneMap(inner, result)
	}
}

func readDoneMap(obj map[string]interface{}, result *scriptResult) {
	if value, ok := obj["url"]; ok {
		result.url = fmt.Sprint(value)
	}
	if value, ok := obj["method"]; ok {
		method := fmt.Sprint(value)
		if method != "<nil>" && method != "undefined" && method != "null" {
			result.method = method
		}
	}
	if value, ok := obj["headers"]; ok {
		result.headers = toHeaderMap(value)
	}
	if value, ok := obj["body"]; ok {
		result.body = []byte(fmt.Sprint(value))
		result.bodySet = true
	}
	if value, ok := obj["status"]; ok {
		if status, err := strconv.Atoi(fmt.Sprint(value)); err == nil {
			result.status = status
			result.statusSet = true
		}
	}
}

func toHeaderMap(value interface{}) map[string]string {
	result := make(map[string]string)
	switch headers := value.(type) {
	case map[string]interface{}:
		for key, item := range headers {
			result[key] = fmt.Sprint(item)
		}
	case map[string]string:
		for key, item := range headers {
			result[key] = item
		}
	}
	return result
}

func headerMap(header http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range header {
		if len(values) > 0 {
			result[key] = strings.Join(values, ",")
		}
	}
	return result
}

func applyScriptRequest(result *scriptResult, request *http.Request) {
	if result == nil {
		return
	}
	if result.method != "" {
		request.Method = result.method
	}
	if result.url != "" && result.url != "<nil>" && result.url != "undefined" && result.url != "null" {
		if parsed, err := url.Parse(result.url); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			request.URL = parsed
			request.Host = parsed.Host
		}
	}
	if result.headers != nil {
		request.Header = make(http.Header)
		for key, value := range result.headers {
			request.Header.Set(key, value)
		}
	}
	if result.bodySet {
		request.Body = io.NopCloser(bytes.NewReader(result.body))
		request.ContentLength = int64(len(result.body))
	}
}

func applyScriptResponse(result *scriptResult, response *http.Response) {
	if result == nil {
		return
	}
	if result.statusSet && result.status > 0 {
		response.StatusCode = result.status
		response.Status = fmt.Sprintf("%d %s", result.status, http.StatusText(result.status))
	}
	if result.headers != nil {
		response.Header = make(http.Header)
		for key, value := range result.headers {
			response.Header.Set(key, value)
		}
	}
	if result.bodySet {
		original := response.Body
		response.Body = struct {
			io.Reader
			io.Closer
		}{Reader: bytes.NewReader(result.body), Closer: original}
		response.ContentLength = int64(len(result.body))
		response.Header.Del("Content-Length")
		response.Header.Del("Content-Encoding")
	}
}
