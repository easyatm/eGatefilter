package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// CaptureHub 维护所有 GUI WebSocket 客户端，用于实时推送抓包摘要。
type CaptureHub struct {
	clients map[*websocket.Conn]struct{}
	mu      sync.Mutex
}

func NewCaptureHub() *CaptureHub {
	return &CaptureHub{clients: make(map[*websocket.Conn]struct{})}
}

func (h *CaptureHub) Add(conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[conn] = struct{}{}
}

func (h *CaptureHub) Remove(conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, conn)
	_ = conn.Close()
}

func (h *CaptureHub) Broadcast(record *CaptureRecord) {
	if h == nil || record == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"type": "capture",
		"data": record,
	})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for conn := range h.clients {
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			_ = conn.Close()
			delete(h.clients, conn)
		}
	}
}

func (h *CaptureHub) BroadcastClear() {
	if h == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{"type": "clear"})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for conn := range h.clients {
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			_ = conn.Close()
			delete(h.clients, conn)
		}
	}
}

func (p *Proxy) StartGUI(addr string) error {
	hub := NewCaptureHub()
	if p.capture != nil {
		p.capture.SetHub(hub)
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           corsMiddleware(p.GUIMux(hub)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}

func (p *Proxy) GUIMux(hub *CaptureHub) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/egatefilter.crl", p.handleCRL)
	mux.HandleFunc("/api/captures", p.handleCaptureList)
	mux.HandleFunc("/api/captures/", p.handleCaptureDetail)
	mux.HandleFunc("/ws/captures", p.handleCaptureWS(hub))
	mux.HandleFunc("/", p.handleGUIStatic())
	return mux
}

func (p *Proxy) handleCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "方法不允许")
		return
	}
	crl, err := p.ca.EmptyCRL()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(crl)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Proxy) handleCaptureList(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		if err := p.capture.Clear(); err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if p.capture != nil && p.capture.hub != nil {
			p.capture.hub.BroadcastClear()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "方法不允许")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	keyword := strings.TrimSpace(r.URL.Query().Get("q"))
	records, err := p.capture.List(limit, offset, keyword)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": records})
}

func (p *Proxy) handleCaptureDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "方法不允许")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/captures/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少抓包ID")
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效抓包ID")
		return
	}
	if len(parts) == 1 {
		record, err := p.capture.Get(id)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "抓包记录不存在")
			return
		}
		writeJSON(w, http.StatusOK, record)
		return
	}
	if len(parts) == 3 && parts[1] == "body" {
		offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)
		body, err := p.capture.ReadBody(id, parts[2], offset, limit)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, body)
		return
	}
	writeJSONError(w, http.StatusNotFound, "接口不存在")
}

func (p *Proxy) handleCaptureWS(hub *CaptureHub) http.HandlerFunc {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("websocket upgrade: %v", err)
			return
		}
		hub.Add(conn)
		defer hub.Remove(conn)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}
}

func (p *Proxy) handleGUIStatic() http.HandlerFunc {
	distDir := p.config.GUI.DistDir
	fileServer := http.FileServer(http.Dir(distDir))
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
			writeJSONError(w, http.StatusNotFound, "接口不存在")
			return
		}
		path := filepath.Join(distDir, filepath.Clean(r.URL.Path))
		if _, err := filepath.Abs(path); err != nil {
			writeJSONError(w, http.StatusBadRequest, "无效路径")
			return
		}
		if _, err := http.Dir(distDir).Open(strings.TrimPrefix(r.URL.Path, "/")); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func ensureCaptureEnabled(m *CaptureManager) error {
	if m == nil {
		return errors.New("抓包功能未启用")
	}
	return nil
}

func formatWsURL(host string) string {
	return fmt.Sprintf("ws://%s/ws/captures", host)
}
