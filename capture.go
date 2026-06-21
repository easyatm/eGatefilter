package main

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const captureBodyChunkLimit = 1024 * 1024

// CaptureManager 负责把抓包元数据写入 SQLite，把包文保存到文件。
type CaptureManager struct {
	db      *sql.DB
	bodyDir string
	hub     *CaptureHub
	mu      sync.Mutex
}

// CaptureRecord 是一次抓包的摘要信息。
type CaptureRecord struct {
	ID                 int64     `json:"id"`
	CreatedAt          time.Time `json:"created_at"`
	Protocol           string    `json:"protocol"`
	Method             string    `json:"method"`
	Scheme             string    `json:"scheme"`
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	URL                string    `json:"url"`
	Path               string    `json:"path"`
	StatusCode         int       `json:"status_code"`
	RuleName           string    `json:"rule_name"`
	Action             string    `json:"action"`
	ClientAddr         string    `json:"client_addr"`
	ServerAddr         string    `json:"server_addr"`
	ProcessPID         uint32    `json:"process_pid"`
	ProcessName        string    `json:"process_name"`
	ProcessPath        string    `json:"process_path"`
	RequestHeaderPath  string    `json:"request_header_path"`
	RequestBodyPath    string    `json:"request_body_path"`
	ResponseHeaderPath string    `json:"response_header_path"`
	ResponseBodyPath   string    `json:"response_body_path"`
	RequestSize        int64     `json:"request_size"`
	ResponseSize       int64     `json:"response_size"`
	DurationMs         int64     `json:"duration_ms"`
	Note               string    `json:"note"`
}

// CaptureBody 是 GUI 查看包文时返回的内容。
type CaptureBody struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Offset     int64  `json:"offset"`
	Limit      int64  `json:"limit"`
	NextOffset int64  `json:"next_offset"`
	Text       string `json:"text"`
	Hex        string `json:"hex"`
	Truncated  bool   `json:"truncated"`
}

func NewCaptureManager(cfg CaptureConfig) (*CaptureManager, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = "capture/capture.sqlite"
	}
	bodyDir := cfg.BodyDir
	if bodyDir == "" {
		bodyDir = "capture/bodies"
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("创建抓包数据库目录失败: %w", err)
	}
	if err := os.MkdirAll(bodyDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建抓包包文目录失败: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开抓包数据库失败: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化 SQLite 选项失败: %w", err)
	}
	mgr := &CaptureManager{db: db, bodyDir: bodyDir}
	if err := mgr.init(); err != nil {
		db.Close()
		return nil, err
	}
	return mgr, nil
}

func (m *CaptureManager) Close() error {
	if m == nil || m.db == nil {
		return nil
	}
	return m.db.Close()
}

func (m *CaptureManager) SetHub(hub *CaptureHub) {
	if m == nil {
		return
	}
	m.hub = hub
}

func (m *CaptureManager) init() error {
	_, err := m.db.Exec(`
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    protocol TEXT NOT NULL,
    method TEXT,
    scheme TEXT,
    host TEXT,
    port INTEGER,
    url TEXT,
    path TEXT,
    status_code INTEGER,
    rule_name TEXT,
    action TEXT,
    client_addr TEXT,
    server_addr TEXT,
	process_pid INTEGER DEFAULT 0,
	process_name TEXT DEFAULT '',
	process_path TEXT DEFAULT '',
    request_header_path TEXT,
    request_body_path TEXT,
    response_header_path TEXT,
    response_body_path TEXT,
    request_size INTEGER DEFAULT 0,
    response_size INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_captures_created_at ON captures(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_captures_protocol ON captures(protocol);
CREATE INDEX IF NOT EXISTS idx_captures_host ON captures(host);
`)
	if err != nil {
		return fmt.Errorf("初始化抓包数据库失败: %w", err)
	}
	_ = m.addColumnIfMissing("process_pid", "INTEGER DEFAULT 0")
	_ = m.addColumnIfMissing("process_name", "TEXT DEFAULT ''")
	_ = m.addColumnIfMissing("process_path", "TEXT DEFAULT ''")
	_, _ = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_captures_process_name ON captures(process_name);`)
	return nil
}

func (m *CaptureManager) addColumnIfMissing(name, typ string) error {
	_, err := m.db.Exec(fmt.Sprintf(`ALTER TABLE captures ADD COLUMN %s %s`, name, typ))
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		return err
	}
	return nil
}

func (m *CaptureManager) Insert(record *CaptureRecord) int64 {
	if m == nil || record == nil {
		return 0
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now()
	}
	m.mu.Lock()
	res, err := m.db.Exec(`
INSERT INTO captures (
    created_at, protocol, method, scheme, host, port, url, path, status_code,
    rule_name, action, client_addr, server_addr, process_pid, process_name, process_path,
    request_header_path, request_body_path, response_header_path, response_body_path,
    request_size, response_size, duration_ms, note
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.CreatedAt.Format(time.RFC3339Nano), record.Protocol, record.Method, record.Scheme,
		record.Host, record.Port, record.URL, record.Path, record.StatusCode, record.RuleName,
		record.Action, record.ClientAddr, record.ServerAddr, record.ProcessPID, record.ProcessName,
		record.ProcessPath, record.RequestHeaderPath, record.RequestBodyPath, record.ResponseHeaderPath, record.ResponseBodyPath,
		record.RequestSize, record.ResponseSize, record.DurationMs, record.Note)
	m.mu.Unlock()
	if err != nil {
		log.Printf("capture insert: %v", err)
		return 0
	}
	id, _ := res.LastInsertId()
	record.ID = id
	if m.hub != nil {
		m.hub.Broadcast(record)
	}
	return id
}

func (m *CaptureManager) UpdateSizes(id, requestSize, responseSize, durationMs int64) {
	if m == nil || id == 0 {
		return
	}
	m.mu.Lock()
	_, err := m.db.Exec(`UPDATE captures SET request_size = ?, response_size = ?, duration_ms = ? WHERE id = ?`, requestSize, responseSize, durationMs, id)
	m.mu.Unlock()
	if err != nil {
		log.Printf("capture update sizes: %v", err)
		return
	}
	if m.hub != nil {
		if record, err := m.Get(id); err == nil {
			m.hub.Broadcast(record)
		}
	}
}

func (m *CaptureManager) List(limit, offset int, keyword string) ([]CaptureRecord, error) {
	if m == nil {
		return nil, errors.New("抓包功能未启用")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, created_at, protocol, method, scheme, host, port, url, path, status_code,
rule_name, action, client_addr, server_addr, process_pid, process_name, process_path, request_header_path, request_body_path,
response_header_path, response_body_path, request_size, response_size, duration_ms, note
FROM captures`
	args := []any{}
	if keyword != "" {
		query += ` WHERE host LIKE ? OR url LIKE ? OR method LIKE ? OR protocol LIKE ? OR process_name LIKE ? OR process_path LIKE ?`
		like := "%" + keyword + "%"
		args = append(args, like, like, like, like, like, like)
	}
	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []CaptureRecord
	for rows.Next() {
		record, err := scanCaptureRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (m *CaptureManager) Get(id int64) (*CaptureRecord, error) {
	if m == nil {
		return nil, errors.New("抓包功能未启用")
	}
	row := m.db.QueryRow(`SELECT id, created_at, protocol, method, scheme, host, port, url, path, status_code,
rule_name, action, client_addr, server_addr, process_pid, process_name, process_path, request_header_path, request_body_path,
response_header_path, response_body_path, request_size, response_size, duration_ms, note
FROM captures WHERE id = ?`, id)
	record, err := scanCaptureRecord(row)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (m *CaptureManager) ReadBody(id int64, part string, offset, limit int64) (*CaptureBody, error) {
	record, err := m.Get(id)
	if err != nil {
		return nil, err
	}
	var fpath string
	switch part {
	case "requestHeader":
		fpath = record.RequestHeaderPath
	case "requestBody":
		fpath = record.RequestBodyPath
	case "responseHeader":
		fpath = record.ResponseHeaderPath
	case "responseBody":
		fpath = record.ResponseBodyPath
	default:
		return nil, fmt.Errorf("未知包文类型: %s", part)
	}
	if fpath == "" {
		return &CaptureBody{}, nil
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > captureBodyChunkLimit {
		limit = captureBodyChunkLimit
	}
	file, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if offset > size {
		offset = size
	}
	buf := make([]byte, limit)
	n, err := file.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	preview := buf[:n]
	nextOffset := offset + int64(n)
	truncated := nextOffset < size
	text := string(preview)
	if !looksText(preview) {
		text = "二进制内容，已显示十六进制预览：\n" + hex.Dump(preview)
	}
	return &CaptureBody{
		Path:       fpath,
		Size:       size,
		Offset:     offset,
		Limit:      limit,
		NextOffset: nextOffset,
		Text:       text,
		Hex:        hex.EncodeToString(preview),
		Truncated:  truncated,
	}, nil
}

func looksText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if !utf8.Valid(data) {
		return false
	}
	bad := 0
	for _, b := range data {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			bad++
		}
	}
	return bad*10 < len(data)
}

func scanCaptureRecord(scanner interface{ Scan(dest ...any) error }) (CaptureRecord, error) {
	var record CaptureRecord
	var createdAt string
	err := scanner.Scan(&record.ID, &createdAt, &record.Protocol, &record.Method, &record.Scheme,
		&record.Host, &record.Port, &record.URL, &record.Path, &record.StatusCode,
		&record.RuleName, &record.Action, &record.ClientAddr, &record.ServerAddr,
		&record.ProcessPID, &record.ProcessName, &record.ProcessPath,
		&record.RequestHeaderPath, &record.RequestBodyPath, &record.ResponseHeaderPath,
		&record.ResponseBodyPath, &record.RequestSize, &record.ResponseSize, &record.DurationMs,
		&record.Note)
	if err != nil {
		return record, err
	}
	record.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return record, nil
}

func (m *CaptureManager) SavePart(prefix, part string, data []byte) string {
	return m.SavePartWithExt(prefix, part, ".bin", data)
}

func (m *CaptureManager) SavePartWithExt(prefix, part, ext string, data []byte) string {
	if m == nil || len(data) == 0 {
		return ""
	}
	if ext == "" {
		ext = ".bin"
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	name := fmt.Sprintf("%s_%s%s", sanitizeSegment(prefix), sanitizeSegment(part), sanitizeSegment(ext))
	fpath := filepath.Join(m.bodyDir, time.Now().Format("20060102"), name)
	if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
		log.Printf("capture mkdir %s: %v", filepath.Dir(fpath), err)
		return ""
	}
	if err := os.WriteFile(fpath, data, 0o644); err != nil {
		log.Printf("capture write %s: %v", fpath, err)
		return ""
	}
	return fpath
}

func (m *CaptureManager) BuildPartPath(prefix, part, ext string) string {
	if m == nil {
		return ""
	}
	if ext == "" {
		ext = ".bin"
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	name := fmt.Sprintf("%s_%s%s", sanitizeSegment(prefix), sanitizeSegment(part), sanitizeSegment(ext))
	return filepath.Join(m.bodyDir, time.Now().Format("20060102"), name)
}

func (m *CaptureManager) SavePartToScope(scope, prefix, part, ext string, data []byte) string {
	if m == nil || len(data) == 0 {
		return ""
	}
	if scope == "" {
		scope = "unknown"
	}
	if ext == "" {
		ext = ".bin"
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	name := fmt.Sprintf("%s_%s%s", sanitizeSegment(prefix), sanitizeSegment(part), sanitizeSegment(ext))
	fpath := filepath.Join(m.bodyDir, sanitizeSegment(scope), name)
	if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
		log.Printf("capture mkdir %s: %v", filepath.Dir(fpath), err)
		return ""
	}
	if err := os.WriteFile(fpath, data, 0o644); err != nil {
		log.Printf("capture write %s: %v", fpath, err)
		return ""
	}
	return fpath
}

func (m *CaptureManager) BuildScopedPartPath(scope, prefix, part, ext string) string {
	if m == nil {
		return ""
	}
	if scope == "" {
		scope = "unknown"
	}
	if ext == "" {
		ext = ".bin"
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	name := fmt.Sprintf("%s_%s%s", sanitizeSegment(prefix), sanitizeSegment(part), sanitizeSegment(ext))
	return filepath.Join(m.bodyDir, sanitizeSegment(scope), name)
}

func captureScope(host string) string {
	host = strings.Trim(host, "[]")
	if host == "" {
		return "unknown"
	}
	return host
}

func captureFilePrefix(start time.Time) string {
	return start.Format("20060102150405.000")
}

func ensureFileForWrite(fpath string) (*os.File, error) {
	if fpath == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
		return nil, err
	}
	return os.Create(fpath)
}

func (p *Proxy) captureHTTPTransaction(protocol string, req *http.Request, resp *http.Response, reqBody []byte, respBody []byte, start time.Time, host string, rule *Rule, clientAddr string) {
	if p.capture == nil || req == nil || resp == nil {
		return
	}
	hostName, port := splitHostPortDefault(host, defaultPortForScheme(protocol))
	ruleName, action := ruleInfo(rule)
	process := lookupProcessByClientAddr(clientAddr)
	scope := captureScope(hostName)
	prefix := captureFilePrefix(start)
	requestHeader := dumpRequestHeader(req)
	responseHeader := dumpResponseHeader(resp)
	record := &CaptureRecord{
		CreatedAt:          start,
		Protocol:           protocol,
		Method:             req.Method,
		Scheme:             protocol,
		Host:               hostName,
		Port:               port,
		URL:                req.URL.String(),
		Path:               req.URL.RequestURI(),
		StatusCode:         resp.StatusCode,
		RuleName:           ruleName,
		Action:             action,
		ClientAddr:         clientAddr,
		ServerAddr:         host,
		ProcessPID:         process.PID,
		ProcessName:        process.Name,
		ProcessPath:        process.Path,
		RequestHeaderPath:  p.capture.SavePartToScope(scope, prefix, "request_header", ".txt", requestHeader),
		RequestBodyPath:    p.capture.SavePartToScope(scope, prefix, "request_body", extensionFromContentType(req.Header.Get("Content-Type"), req.URL.Path), reqBody),
		ResponseHeaderPath: p.capture.SavePartToScope(scope, prefix, "response_header", ".txt", responseHeader),
		ResponseBodyPath:   p.capture.BuildScopedPartPath(scope, prefix, "response_body", extensionFromContentType(resp.Header.Get("Content-Type"), req.URL.Path)),
		RequestSize:        int64(len(reqBody)),
		ResponseSize:       int64(len(respBody)),
		DurationMs:         time.Since(start).Milliseconds(),
	}
	p.capture.Insert(record)
}

func (p *Proxy) insertHTTPRecord(protocol string, req *http.Request, resp *http.Response, start time.Time, host string, rule *Rule, clientAddr string, requestHeaderPath, requestBodyPath, responseHeaderPath, responseBodyPath string, requestSize, responseSize int64) int64 {
	if p.capture == nil || req == nil || resp == nil {
		return 0
	}
	hostName, port := splitHostPortDefault(host, defaultPortForScheme(protocol))
	ruleName, action := ruleInfo(rule)
	process := lookupProcessByClientAddr(clientAddr)
	record := &CaptureRecord{
		CreatedAt:          start,
		Protocol:           protocol,
		Method:             req.Method,
		Scheme:             protocol,
		Host:               hostName,
		Port:               port,
		URL:                req.URL.String(),
		Path:               req.URL.RequestURI(),
		StatusCode:         resp.StatusCode,
		RuleName:           ruleName,
		Action:             action,
		ClientAddr:         clientAddr,
		ServerAddr:         host,
		ProcessPID:         process.PID,
		ProcessName:        process.Name,
		ProcessPath:        process.Path,
		RequestHeaderPath:  requestHeaderPath,
		RequestBodyPath:    requestBodyPath,
		ResponseHeaderPath: responseHeaderPath,
		ResponseBodyPath:   responseBodyPath,
		RequestSize:        requestSize,
		ResponseSize:       responseSize,
		DurationMs:         time.Since(start).Milliseconds(),
	}
	return p.capture.Insert(record)
}

func extensionFromContentType(contentType, urlPath string) string {
	if ext := filepath.Ext(urlPath); ext != "" && len(ext) <= 12 {
		return ext
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err == nil {
		switch strings.ToLower(mediaType) {
		case "text/html":
			return ".html"
		case "text/css":
			return ".css"
		case "text/plain":
			return ".txt"
		case "application/json":
			return ".json"
		case "application/javascript", "text/javascript":
			return ".js"
		case "application/xml", "text/xml":
			return ".xml"
		case "image/png":
			return ".png"
		case "image/jpeg":
			return ".jpg"
		case "image/gif":
			return ".gif"
		case "image/webp":
			return ".webp"
		case "application/pdf":
			return ".pdf"
		}
		if exts, err := mime.ExtensionsByType(mediaType); err == nil && len(exts) > 0 {
			return exts[0]
		}
	}
	return ".bin"
}

type captureReadCloser struct {
	src  io.ReadCloser
	file *os.File
	n    int64
}

func (c *captureReadCloser) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	if n > 0 {
		if c.file != nil {
			_, _ = c.file.Write(p[:n])
		}
		c.n += int64(n)
	}
	return n, err
}

func (c *captureReadCloser) Close() error {
	if c.file != nil {
		_ = c.file.Close()
	}
	return c.src.Close()
}

func (p *Proxy) captureTCP(protocol, host string, rule *Rule, clientAddr string, requestBytes, responseBytes int64, start time.Time, requestPath, responsePath, note string) {
	if p.capture == nil {
		return
	}
	hostName, port := splitHostPortDefault(host, 0)
	ruleName, action := ruleInfo(rule)
	process := lookupProcessByClientAddr(clientAddr)
	record := &CaptureRecord{
		CreatedAt:        start,
		Protocol:         protocol,
		Host:             hostName,
		Port:             port,
		URL:              host,
		Path:             host,
		RuleName:         ruleName,
		Action:           action,
		ClientAddr:       clientAddr,
		ServerAddr:       host,
		ProcessPID:       process.PID,
		ProcessName:      process.Name,
		ProcessPath:      process.Path,
		RequestBodyPath:  requestPath,
		ResponseBodyPath: responsePath,
		RequestSize:      requestBytes,
		ResponseSize:     responseBytes,
		DurationMs:       time.Since(start).Milliseconds(),
		Note:             note,
	}
	p.capture.Insert(record)
}

func captureAndReplaceBody(resp *http.Response) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return body
}

func readAndReplaceRequestBody(req *http.Request) []byte {
	if req == nil || req.Body == nil {
		return nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return body
}

func dumpRequestHeader(req *http.Request) []byte {
	if req == nil {
		return nil
	}
	var b strings.Builder
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = req.URL.String()
	}
	fmt.Fprintf(&b, "%s %s %s\r\n", req.Method, uri, req.Proto)
	_ = req.Header.Write(&b)
	b.WriteString("\r\n")
	return []byte(b.String())
}

func dumpResponseHeader(resp *http.Response) []byte {
	if resp == nil {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\r\n", resp.Proto, resp.Status)
	_ = resp.Header.Write(&b)
	b.WriteString("\r\n")
	return []byte(b.String())
}

func splitHostPortDefault(host string, defaultPort int) (string, int) {
	hostName, portText, err := netSplitHostPort(host)
	if err != nil {
		return stripPort(host), defaultPort
	}
	port := defaultPort
	fmt.Sscanf(portText, "%d", &port)
	return strings.Trim(hostName, "[]"), port
}

func netSplitHostPort(host string) (string, string, error) {
	if strings.Contains(host, ":") {
		return splitHostPort(host)
	}
	return host, "", fmt.Errorf("缺少端口")
}

func splitHostPort(host string) (string, string, error) {
	lastColon := strings.LastIndex(host, ":")
	if lastColon < 0 {
		return host, "", fmt.Errorf("缺少端口")
	}
	return host[:lastColon], host[lastColon+1:], nil
}

func defaultPortForScheme(scheme string) int {
	if scheme == "https" {
		return 443
	}
	if scheme == "http" {
		return 80
	}
	return 0
}

func ruleInfo(rule *Rule) (string, string) {
	if rule == nil {
		return "", ActionPassthrough.String()
	}
	return rule.Name, rule.Action.String()
}
