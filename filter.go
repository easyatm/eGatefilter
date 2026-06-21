package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// FilterResponse reads, optionally filters, and replaces the response body in-place.
// It handles gzip Content-Encoding transparently.
// Non-text content types are passed through unchanged.
func FilterResponse(resp *http.Response, rules []ContentRule, urlPath string) {
	if len(rules) == 0 {
		return
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if !isTextContent(contentType) {
		return
	}

	encoding := resp.Header.Get("Content-Encoding")
	isGzip := strings.EqualFold(encoding, "gzip")

	var reader io.Reader = resp.Body
	if isGzip {
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			// Cannot decompress — skip filtering
			return
		}
		defer gr.Close()
		reader = gr
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return
	}
	resp.Body.Close()

	filtered := applyRules(body, rules, urlPath)

	// Re-encode if the original was gzip and nothing changed, otherwise send plain.
	var outBody []byte
	if isGzip {
		if bytes.Equal(body, filtered) {
			// Re-compress unchanged content to preserve encoding.
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			_, _ = gw.Write(filtered)
			_ = gw.Close()
			outBody = buf.Bytes()
		} else {
			// Content changed — send as plain text.
			resp.Header.Del("Content-Encoding")
			outBody = filtered
		}
	} else {
		outBody = filtered
	}

	resp.Body = io.NopCloser(bytes.NewReader(outBody))
	resp.ContentLength = int64(len(outBody))
	resp.Header.Del("Transfer-Encoding")
}

// applyRules runs every ContentRule against body in order.
// When a content rule has Paths configured, it only applies to matching URL paths.
func applyRules(body []byte, rules []ContentRule, urlPath string) []byte {
	for _, r := range rules {
		if len(r.Paths) > 0 && !matchAnyPath(r.Paths, urlPath) {
			continue
		}
		if r.Regex {
			re, err := regexp.Compile(r.Match)
			if err == nil {
				body = re.ReplaceAll(body, []byte(r.Replace))
			}
		} else {
			body = bytes.ReplaceAll(body, []byte(r.Match), []byte(r.Replace))
		}
	}
	return body
}

func matchAnyPath(patterns []string, urlPath string) bool {
	for _, p := range patterns {
		if wildcardMatch(p, urlPath) {
			return true
		}
	}
	return false
}

// isTextContent returns true for MIME types we should attempt to filter.
func isTextContent(ct string) bool {
	for _, sub := range []string{
		"text/", "application/json", "application/javascript",
		"application/xml", "application/xhtml", "+xml",
	} {
		if strings.Contains(ct, sub) {
			return true
		}
	}
	return false
}
