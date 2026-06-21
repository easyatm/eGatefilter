package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"crypto/md5"
)

// unsafeWin matches characters forbidden in Windows/POSIX filenames.
var unsafeWin = regexp.MustCompile(`[<>:"|?*\x00-\x1f]`)

// cacheResponse reads resp.Body, writes it to CacheDir, then replaces resp.Body
// with a fresh reader so callers can still write the response to the client.
// host should be the bare hostname (no port). urlPath and rawQuery come from the
// request URL. The disk write is done in a background goroutine so it does not
// block the proxy.
func (p *Proxy) cacheResponse(method, host, urlPath, rawQuery string, resp *http.Response) {
	if p.config.CacheDir == "" {
		return
	}
	if !responseCanHaveBody(method, resp.StatusCode) {
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		// Avoid overwriting existing cache entries with empty bodies
		// from edge responses.
		return
	}

	go func() {
		fpath := buildCachePath(p.config.CacheDir, host, urlPath, rawQuery)
		if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
			log.Printf("cache mkdir %s: %v", filepath.Dir(fpath), err)
			return
		}
		if err := os.WriteFile(fpath, body, 0o644); err != nil {
			log.Printf("cache write %s: %v", fpath, err)
			return
		}
		log.Printf("cache saved: %s", fpath)
	}()
}

func responseCanHaveBody(method string, statusCode int) bool {
	if strings.EqualFold(method, http.MethodHead) {
		return false
	}
	if statusCode >= 100 && statusCode < 200 {
		return false
	}
	if statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		return false
	}
	return true
}

// buildCachePath constructs a filesystem path mirroring the URL structure:
//
//	{cacheDir}/{host}/{urlPath}[@{queryHash}]
//
// Examples:
//
//	cache/example.com/index                        (path "/")
//	cache/example.com/article/news                 (path "/article/news")
//	cache/example.com/search@1a2b3c4d              (path "/search?q=go")
//	cache/example.com/static/app@5e6f7a8b.js       (path "/static/app.js?v=2")
func buildCachePath(cacheDir, host, urlPath, rawQuery string) string {
	// Normalise path
	if urlPath == "" {
		urlPath = "/"
	}

	// Split on "/" and sanitize each segment
	segments := strings.Split(urlPath, "/")
	for i, s := range segments {
		segments[i] = sanitizeSegment(s)
	}

	// Last segment is the "filename"; empty means the URL ended with "/"
	last := segments[len(segments)-1]
	if last == "" {
		last = "index"
		segments[len(segments)-1] = last
	}

	// Append a short query hash when a query string is present
	if rawQuery != "" {
		sum := md5.Sum([]byte(rawQuery))
		hash := hex.EncodeToString(sum[:4]) // 8 hex chars
		ext := filepath.Ext(last)
		base := strings.TrimSuffix(last, ext)
		segments[len(segments)-1] = fmt.Sprintf("%s@%s%s", base, hash, ext)
	}

	rel := strings.Join(segments, string(filepath.Separator))
	return filepath.Join(cacheDir, sanitizeSegment(host), rel)
}

// sanitizeSegment replaces characters that are unsafe in filenames and
// truncates overly long segments.
func sanitizeSegment(s string) string {
	s = unsafeWin.ReplaceAllString(s, "_")
	s = strings.ReplaceAll(s, "\\", "_")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
