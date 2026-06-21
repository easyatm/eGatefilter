package main

import (
	"bytes"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// applyFileReplacement applies rule.File replacements to a response.
// Returns true when replacement succeeded and response body was swapped.
func (p *Proxy) applyFileReplacement(resp *http.Response, host, urlPath string, rule *Rule) bool {
	if rule == nil || len(rule.File) == 0 {
		return false
	}
	for _, fr := range rule.File {
		match := strings.TrimSpace(fr.Match)
		if match == "" {
			continue
		}
		captures, ok := wildcardCaptures(match, urlPath)
		if !ok {
			continue
		}

		localPath := resolveLocalReplacementPath(host, urlPath, fr, captures)
		data, err := os.ReadFile(localPath)
		if err != nil {
			log.Printf("file replace read %s: %v", localPath, err)
			continue
		}

		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.StatusCode = http.StatusOK
		resp.Status = "200 OK"
		resp.ContentLength = int64(len(data))
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Transfer-Encoding")
		resp.Header.Del("Content-Range")
		resp.Header.Del("Etag")
		resp.Header.Del("Last-Modified")
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))

		if ctype := mime.TypeByExtension(strings.ToLower(filepath.Ext(localPath))); ctype != "" {
			resp.Header.Set("Content-Type", ctype)
		}
		log.Printf("file replaced: %s -> %s", urlPath, localPath)
		return true
	}
	return false
}

func resolveLocalReplacementPath(host, urlPath string, fr FileRuleConfig, captures []string) string {
	local := strings.TrimSpace(fr.Local)
	if local == "" {
		return filepath.Join("filter", sanitizeSegment(host), safePathFromURL(urlPath))
	}

	for _, c := range captures {
		local = strings.Replace(local, "*", c, 1)
	}
	local = filepath.FromSlash(local)

	// Directory mapping shortcut:
	// match "/i18n/*" + local "filter/claude.ai/i18n/" + path "/i18n/en-US.json"
	// => filter/claude.ai/i18n/en-US.json
	if strings.HasSuffix(fr.Local, "/") || strings.HasSuffix(fr.Local, "\\") {
		suffix := ""
		if len(captures) > 0 {
			suffix = captures[len(captures)-1]
		}
		return filepath.Join(local, filepath.FromSlash(strings.TrimLeft(suffix, "/")))
	}
	return local
}

func safePathFromURL(urlPath string) string {
	parts := strings.Split(strings.TrimPrefix(urlPath, "/"), "/")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if s == "." || s == ".." {
			s = "_"
		}
		out = append(out, sanitizeSegment(s))
	}
	if len(out) == 0 {
		return "index"
	}
	return filepath.Join(out...)
}
