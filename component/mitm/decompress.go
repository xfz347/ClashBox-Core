package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// decompressBody 按 Content-Encoding 解压请求/响应体, 供脚本与正则处理。
// 解压失败时原样返回, 保证不影响正常转发。
func decompressBody(data []byte, encoding string) []byte {
	if len(data) == 0 {
		return data
	}
	for _, raw := range strings.Split(strings.ToLower(encoding), ",") {
		enc := strings.TrimSpace(raw)
		switch enc {
		case "gzip", "x-gzip":
			if r, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
				if out, rerr := io.ReadAll(r); rerr == nil {
					data = out
				}
				_ = r.Close()
			}
		case "deflate":
			// HTTP 的 deflate 实际可能是 zlib 包装或裸 deflate, 两种都尝试
			if r, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
				if out, rerr := io.ReadAll(r); rerr == nil {
					data = out
				}
				_ = r.Close()
			} else if r := flate.NewReader(bytes.NewReader(data)); r != nil {
				if out, rerr := io.ReadAll(r); rerr == nil {
					data = out
				}
				_ = r.Close()
			}
		case "br":
			if out, err := io.ReadAll(brotli.NewReader(bytes.NewReader(data))); err == nil {
				data = out
			}
		case "zstd":
			if r, err := zstd.NewReader(bytes.NewReader(data)); err == nil {
				if out, rerr := io.ReadAll(r); rerr == nil {
					data = out
				}
				r.Close()
			}
		}
	}
	return data
}
