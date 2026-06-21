package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// hop-by-hop headers that must not be forwarded.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailers", "Transfer-Encoding", "Upgrade",
}

// removeHopHeaders removes hop-by-hop headers from h.
func removeHopHeaders(h http.Header) {
	for _, f := range strings.Split(h.Get("Connection"), ",") {
		h.Del(strings.TrimSpace(f))
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// StartHTTP starts the HTTP proxy listener on addr.
func (p *Proxy) StartHTTP(addr string) error {
	server := &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(p.handleHTTP),
		// Disable HTTP/2 so we can handle everything at HTTP/1.1 level.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	return server.ListenAndServe()
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}
	p.handlePlainHTTP(w, r)
}

// handleCONNECT services a CONNECT tunnel request (HTTPS proxying).
func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	rule := p.rules.Match(host)

	if rule != nil && rule.Action == ActionBlock {
		http.Error(w, fmt.Sprintf("Blocked by rule %q", rule.Name), http.StatusForbidden)
		log.Printf("CONNECT blocked: %s (rule: %s)", host, rule.Name)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		log.Printf("hijack: %v", err)
		return
	}

	_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	if rule != nil && rule.Action == ActionFilter {
		go p.doMITM(conn, host, rule)
	} else if rule != nil && rule.Action == ActionRedirect && rule.Target != "" {
		log.Printf("CONNECT redirect: %s -> %s (rule: %s)", host, rule.Target, rule.Name)
		go p.rawTunnel(conn, rule.Target, "tcp", rule, r.RemoteAddr, start)
	} else {
		go p.rawTunnel(conn, host, "tcp", rule, r.RemoteAddr, start)
	}
}

// handlePlainHTTP proxies a plain HTTP request.
func (p *Proxy) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}

	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	rule := p.rules.Match(host)

	if rule != nil && rule.Action == ActionBlock {
		http.Error(w, fmt.Sprintf("Blocked by rule %q", rule.Name), http.StatusForbidden)
		log.Printf("HTTP blocked: %s (rule: %s)", host, rule.Name)
		return
	}

	outURL := *r.URL
	if rule != nil && rule.Action == ActionRedirect && rule.Target != "" {
		log.Printf("HTTP redirect: %s -> %s (rule: %s)", host, rule.Target, rule.Name)
		outURL.Host = rule.Target
	}

	reqBody := readAndReplaceRequestBody(r)
	outReq, err := http.NewRequest(r.Method, outURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	outReq.Header = r.Header.Clone()
	removeHopHeaders(outReq.Header)

	// 启用过滤或抓包时禁用压缩，确保过滤和 GUI 预览拿到可读明文。
	if (rule != nil && rule.Action == ActionFilter) || p.capture != nil {
		outReq.Header.Del("Accept-Encoding")
	}

	dialCtx := (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	if p.upstream != nil {
		dialCtx = p.upstream.DialContext
	}
	transport := &http.Transport{
		DialContext:         dialCtx,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 60 * time.Second,
	}

	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if rule != nil && rule.Action == ActionFilter {
		hostNoPort := stripPort(r.URL.Host)
		replaced := p.applyFileReplacement(resp, hostNoPort, r.URL.Path, rule)
		shouldTextFilter := rule.ShouldFilterPath(r.URL.Path)
		if !replaced && shouldTextFilter {
			FilterResponse(resp, rule.Content, r.URL.Path)
		}
		if replaced || shouldTextFilter {
			// Cache after replacement/filtering; cacheResponse replaces resp.Body with a fresh reader.
			p.cacheResponse(r.Method, hostNoPort, r.URL.Path, r.URL.RawQuery, resp)
		}
	}
	removeHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	recordID, streamBody := p.prepareHTTPStreamCapture("http", outReq, resp, reqBody, start, host, rule, r.RemoteAddr)
	_, _ = io.Copy(w, resp.Body)
	if recordID != 0 && streamBody != nil {
		p.capture.UpdateSizes(recordID, int64(len(reqBody)), streamBody.n, time.Since(start).Milliseconds())
	}
}

// doMITM performs TLS interception on conn targeting host (host:port).
func (p *Proxy) doMITM(conn net.Conn, host string, rule *Rule) {
	tlsCfg, err := p.ca.TLSServerConfig(host)
	if err != nil {
		log.Printf("MITM cert for %s: %v", host, err)
		conn.Close()
		return
	}

	clientTLS := tls.Server(conn, tlsCfg)
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("MITM TLS handshake with client (%s): %v", host, err)
		clientTLS.Close()
		return
	}
	log.Printf("MITM: %s (rule: %s)", host, rule.Name)

	serverTLS, err := p.tlsDialHost(host)
	if err != nil {
		log.Printf("MITM: connect to real server %s: %v", host, err)
		clientTLS.Close()
		return
	}

	p.bridgeHTTP(clientTLS, serverTLS, host, rule, "https")
}

// bridgeHTTP reads HTTP/1.x requests from client, forwards them to server,
// filters responses, caches them, and writes back to client.
// Both connections are closed when the function returns.
func (p *Proxy) bridgeHTTP(client, server net.Conn, host string, rule *Rule, protocol string) {
	defer client.Close()
	defer server.Close()

	clientBR := bufio.NewReader(client)
	serverBR := bufio.NewReader(server)

	for {
		start := time.Now()
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			return
		}
		reqBody := readAndReplaceRequestBody(req)

		// 启用过滤或抓包时禁用压缩，确保过滤和 GUI 预览拿到可读明文。
		if (rule != nil && rule.Action == ActionFilter) || p.capture != nil {
			req.Header.Del("Accept-Encoding")
		}
		removeHopHeaders(req.Header)

		if err := req.Write(server); err != nil {
			return
		}

		resp, err := http.ReadResponse(serverBR, req)
		if err != nil {
			return
		}

		if rule != nil && rule.Action == ActionFilter {
			hostNoPort := stripPort(host)
			replaced := p.applyFileReplacement(resp, hostNoPort, req.URL.Path, rule)
			shouldTextFilter := rule.ShouldFilterPath(req.URL.Path)
			if !replaced && shouldTextFilter {
				FilterResponse(resp, rule.Content, req.URL.Path)
			}
			if replaced || shouldTextFilter {
				// cacheResponse replaces resp.Body so resp.Write below still works.
				p.cacheResponse(req.Method, hostNoPort, req.URL.Path, req.URL.RawQuery, resp)
			}
		}
		recordID, streamBody := p.prepareHTTPStreamCapture(protocol, req, resp, reqBody, start, host, rule, client.RemoteAddr().String())

		if err := resp.Write(client); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()
		if recordID != 0 && streamBody != nil {
			p.capture.UpdateSizes(recordID, int64(len(reqBody)), streamBody.n, time.Since(start).Milliseconds())
		}

		if req.Close || resp.Close {
			return
		}
	}
}

func (p *Proxy) prepareHTTPStreamCapture(protocol string, req *http.Request, resp *http.Response, reqBody []byte, start time.Time, host string, rule *Rule, clientAddr string) (int64, *captureReadCloser) {
	if p.capture == nil || req == nil || resp == nil || resp.Body == nil {
		return 0, nil
	}
	hostName, _ := splitHostPortDefault(host, defaultPortForScheme(protocol))
	scope := captureScope(hostName)
	prefix := captureFilePrefix(start)
	requestHeaderPath := p.capture.SavePartToScope(scope, prefix, "request_header", ".txt", dumpRequestHeader(req))
	requestBodyPath := p.capture.SavePartToScope(scope, prefix, "request_body", extensionFromContentType(req.Header.Get("Content-Type"), req.URL.Path), reqBody)
	responseHeaderPath := p.capture.SavePartToScope(scope, prefix, "response_header", ".txt", dumpResponseHeader(resp))
	responseBodyPath := p.capture.BuildScopedPartPath(scope, prefix, "response_body", extensionFromContentType(resp.Header.Get("Content-Type"), req.URL.Path))
	file, err := ensureFileForWrite(responseBodyPath)
	if err != nil {
		log.Printf("capture response body create %s: %v", responseBodyPath, err)
	}
	streamBody := &captureReadCloser{src: resp.Body, file: file}
	resp.Body = streamBody
	recordID := p.insertHTTPRecord(protocol, req, resp, start, host, rule, clientAddr, requestHeaderPath, requestBodyPath, responseHeaderPath, responseBodyPath, int64(len(reqBody)), 0)
	return recordID, streamBody
}

// rawTunnel creates a simple bidirectional byte tunnel from conn to target,
// routing through the upstream proxy if configured.
func (p *Proxy) rawTunnel(conn net.Conn, target, protocol string, rule *Rule, clientAddr string, start time.Time) {
	defer conn.Close()

	remote, err := p.upstream.Dial(target)
	if err != nil {
		log.Printf("tunnel dial %s: %v", target, err)
		return
	}
	defer remote.Close()

	hostName, _ := splitHostPortDefault(target, 0)
	scope := captureScope(hostName)
	prefix := captureFilePrefix(start)
	requestPath, responsePath := "", ""
	if p.capture != nil {
		requestPath = p.capture.BuildScopedPartPath(scope, prefix, "request_stream", ".bin")
		responsePath = p.capture.BuildScopedPartPath(scope, prefix, "response_stream", ".bin")
	}
	type tunnelCount struct {
		direction string
		bytes     int64
	}
	done := make(chan tunnelCount, 2)
	go func() {
		n, _ := copyCaptureStream(remote, conn, requestPath)
		done <- tunnelCount{direction: "request", bytes: n}
	}()
	go func() {
		n, _ := copyCaptureStream(conn, remote, responsePath)
		done <- tunnelCount{direction: "response", bytes: n}
	}()
	first := <-done
	requestBytes := int64(0)
	responseBytes := int64(0)
	if first.direction == "request" {
		requestBytes = first.bytes
	} else {
		responseBytes = first.bytes
	}
	if protocol == "tcp" {
		p.captureTCP(protocol, target, rule, clientAddr, requestBytes, responseBytes, start, requestPath, responsePath, "原始TCP隧道按双向流保存包文")
	}
}

func copyCaptureStream(dst io.Writer, src io.Reader, capturePath string) (int64, error) {
	if capturePath == "" {
		return io.Copy(dst, src)
	}
	if err := os.MkdirAll(filepath.Dir(capturePath), 0o755); err != nil {
		log.Printf("capture stream mkdir %s: %v", filepath.Dir(capturePath), err)
		return io.Copy(dst, src)
	}
	file, err := os.Create(capturePath)
	if err != nil {
		log.Printf("capture stream create %s: %v", capturePath, err)
		return io.Copy(dst, src)
	}
	defer file.Close()
	return io.Copy(io.MultiWriter(dst, file), src)
}
