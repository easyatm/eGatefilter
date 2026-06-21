package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socks5Ver = byte(0x05)

	// Authentication methods
	socks5AuthNone     = byte(0x00)
	socks5AuthNoAccept = byte(0xFF)

	// Commands
	socks5CmdConnect = byte(0x01)

	// Address types
	socks5AtypIPv4   = byte(0x01)
	socks5AtypDomain = byte(0x03)
	socks5AtypIPv6   = byte(0x04)

	// Reply codes
	socks5RepSuccess   = byte(0x00) // succeeded
	socks5RepFailed    = byte(0x01) // general SOCKS server failure
	socks5RepDenied    = byte(0x02) // connection not allowed by ruleset
	socks5RepCmdUnsup  = byte(0x07) // command not supported
	socks5RepAtypUnsup = byte(0x08) // address type not supported
)

// socks5Reply sends a SOCKS5 reply with an IPv4 bind address of 0.0.0.0:0.
func socks5Reply(conn net.Conn, rep byte) {
	_, _ = conn.Write([]byte{socks5Ver, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
}

// StartSOCKS5 starts the SOCKS5 proxy listener on addr.
func (p *Proxy) StartSOCKS5(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen on %s: %w", addr, err)
	}
	log.Printf("SOCKS5 listening on %s", addr)
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("socks5 accept: %w", err)
		}
		go p.handleSOCKS5(conn)
	}
}

func (p *Proxy) handleSOCKS5(conn net.Conn) {
	start := time.Now()
	clientAddr := conn.RemoteAddr().String()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("socks5 panic: %v", r)
			conn.Close()
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// ── Greeting ────────────────────────────────────────────────────────────
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != socks5Ver {
		conn.Close()
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		conn.Close()
		return
	}

	hasNoAuth := false
	for _, m := range methods {
		if m == socks5AuthNone {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		_, _ = conn.Write([]byte{socks5Ver, socks5AuthNoAccept})
		conn.Close()
		return
	}
	_, _ = conn.Write([]byte{socks5Ver, socks5AuthNone})

	// ── Request ──────────────────────────────────────────────────────────────
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHdr); err != nil || reqHdr[0] != socks5Ver {
		conn.Close()
		return
	}
	if reqHdr[1] != socks5CmdConnect {
		socks5Reply(conn, socks5RepCmdUnsup)
		conn.Close()
		return
	}

	// Parse destination address.
	var host string
	switch reqHdr[3] {
	case socks5AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			conn.Close()
			return
		}
		host = net.IP(addr).String()
	case socks5AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			conn.Close()
			return
		}
		host = "[" + net.IP(addr).String() + "]"
	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return
		}
		name := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			conn.Close()
			return
		}
		host = string(name)
	default:
		socks5Reply(conn, socks5RepAtypUnsup)
		conn.Close()
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		conn.Close()
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))
	target := net.JoinHostPort(host, strconv.Itoa(port))

	// ── Rule matching ────────────────────────────────────────────────────────
	rule := p.rules.Match(fmt.Sprintf("%s:%d", host, port))

	if rule != nil && rule.Action == ActionBlock {
		log.Printf("SOCKS5 blocked: %s (rule: %s)", target, rule.Name)
		socks5Reply(conn, socks5RepDenied)
		conn.Close()
		return
	}

	// ── Reply success ────────────────────────────────────────────────────────
	socks5Reply(conn, socks5RepSuccess)
	_ = conn.SetDeadline(time.Time{}) // remove deadline

	// ── Dispatch ─────────────────────────────────────────────────────────────
	if rule != nil && rule.Action == ActionFilter {
		// Determine transport by port convention.
		if isTLSPort(port) {
			log.Printf("SOCKS5 MITM: %s (rule: %s)", target, rule.Name)
			p.doMITM(conn, target, rule)
		} else {
			// Plain HTTP — connect to server and bridge with content filtering.
			log.Printf("SOCKS5 HTTP filter: %s (rule: %s)", target, rule.Name)
			remote, err := p.upstream.Dial(target)
			if err != nil {
				log.Printf("SOCKS5 connect to %s: %v", target, err)
				conn.Close()
				return
			}
			p.bridgeHTTP(conn, remote, host, rule, "http")
		}
	} else if rule != nil && rule.Action == ActionRedirect && rule.Target != "" {
		log.Printf("SOCKS5 redirect: %s -> %s (rule: %s)", target, rule.Target, rule.Name)
		p.rawTunnel(conn, rule.Target, "tcp", rule, clientAddr, start)
	} else {
		p.rawTunnel(conn, target, "tcp", rule, clientAddr, start)
	}
}

// isTLSPort returns true for ports commonly used for TLS traffic.
func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 993, 995, 465, 636, 5061:
		return true
	}
	return false
}
