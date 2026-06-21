package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// UpstreamConfig holds outbound proxy settings.
type UpstreamConfig struct {
	// type: "none" (direct) | "socks5" | "pac"
	Type       string `json:"type"`
	Socks5Addr string `json:"socks5_addr"` // for type=socks5, e.g. "127.0.0.1:7890"
	PACFile    string `json:"pac_file"`    // for type=pac: local file path
	PACURL     string `json:"pac_url"`     // for type=pac: remote URL (used if pac_file is empty)
}

// proxyEntry is one directive returned by FindProxyForURL or the config.
type proxyEntry struct {
	Type string // "DIRECT" | "SOCKS5" | "PROXY"
	Addr string // "host:port", empty for DIRECT
}

// UpstreamDialer routes outbound connections through a configured upstream proxy.
// All methods accept a nil receiver and fall back to direct connections.
type UpstreamDialer struct {
	cfg *UpstreamConfig
	pac *PACEvaluator
}

// NewUpstreamDialer creates an UpstreamDialer from the config section.
// Returns nil (direct mode) when cfg is nil or type is "none".
func NewUpstreamDialer(cfg *UpstreamConfig) (*UpstreamDialer, error) {
	if cfg == nil || strings.ToLower(cfg.Type) == "" || strings.ToLower(cfg.Type) == "none" {
		return nil, nil
	}
	d := &UpstreamDialer{cfg: cfg}
	if strings.ToLower(cfg.Type) == "pac" {
		pac, err := NewPACEvaluator(cfg.PACFile, cfg.PACURL)
		if err != nil {
			return nil, fmt.Errorf("load PAC: %w", err)
		}
		d.pac = pac
	}
	return d, nil
}

// Dial returns a TCP connection to addr ("host:port") via the upstream proxy.
func (d *UpstreamDialer) Dial(addr string) (net.Conn, error) {
	entry, err := d.resolve(addr)
	if err != nil {
		return nil, err
	}
	return connectVia(entry, addr)
}

// DialTLS wraps Dial with a TLS handshake using serverName.
func (d *UpstreamDialer) DialTLS(addr, serverName string) (*tls.Conn, error) {
	conn, err := d.Dial(addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: serverName,
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// DialContext is compatible with net.Dialer.DialContext for use in http.Transport.
func (d *UpstreamDialer) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	return d.Dial(addr)
}

// resolve decides which proxy to use for a given addr.
func (d *UpstreamDialer) resolve(addr string) (proxyEntry, error) {
	if d == nil {
		return proxyEntry{Type: "DIRECT"}, nil
	}
	switch strings.ToLower(d.cfg.Type) {
	case "socks5":
		return proxyEntry{Type: "SOCKS5", Addr: d.cfg.Socks5Addr}, nil
	case "pac":
		host, _, _ := net.SplitHostPort(addr)
		syntheticURL := "https://" + addr + "/"
		entry, err := d.pac.FindProxy(syntheticURL, host)
		if err != nil {
			// Fallback to DIRECT on PAC errors
			return proxyEntry{Type: "DIRECT"}, nil
		}
		return entry, nil
	default:
		return proxyEntry{Type: "DIRECT"}, nil
	}
}

// connectVia establishes a connection to targetAddr via the given proxy entry.
func connectVia(p proxyEntry, targetAddr string) (net.Conn, error) {
	switch strings.ToUpper(p.Type) {
	case "SOCKS5", "SOCKS":
		return dialViaSocks5(p.Addr, targetAddr)
	case "PROXY", "HTTPS":
		return dialViaCONNECT(p.Addr, targetAddr)
	default: // "DIRECT" or anything else
		return net.DialTimeout("tcp", targetAddr, 30*time.Second)
	}
}

// dialViaSocks5 tunnels through a SOCKS5 proxy (RFC 1928, no-auth).
func dialViaSocks5(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("socks5 upstream %s: %w", proxyAddr, err)
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bad target addr %q: %w", targetAddr, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Greeting: VER=5, NMETHODS=1, METHOD=NO AUTH
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil || resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 upstream auth rejected")
	}

	// CONNECT request
	req := []byte{0x05, 0x01, 0x00} // VER CMD RSV
	ip := net.ParseIP(host)
	if ip4 := func() net.IP {
		if ip != nil {
			return ip.To4()
		}
		return nil
	}(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip != nil {
		if ip6 := ip.To16(); ip6 != nil {
			req = append(req, 0x04)
			req = append(req, ip6...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read reply header: VER REP RSV ATYP
	replyHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHdr); err != nil {
		conn.Close()
		return nil, err
	}
	if replyHdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 upstream refused connect (code %d)", replyHdr[1])
	}
	// Drain BND.ADDR + BND.PORT
	switch replyHdr[3] {
	case 0x01:
		_, _ = io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		lb := make([]byte, 1)
		_, _ = io.ReadFull(conn, lb)
		_, _ = io.ReadFull(conn, make([]byte, int(lb[0])+2))
	case 0x04:
		_, _ = io.ReadFull(conn, make([]byte, 16+2))
	}
	return conn, nil
}

// dialViaCONNECT tunnels through an HTTP CONNECT proxy.
func dialViaCONNECT(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("http upstream %s: %w", proxyAddr, err)
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n",
		targetAddr, targetAddr)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http upstream CONNECT: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("http upstream CONNECT %s: %s", targetAddr, resp.Status)
	}
	return conn, nil
}
