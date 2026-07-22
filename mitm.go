package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// CertManager loads the CA and issues leaf certificates on demand.
type CertManager struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	crlURL string
	cache  map[string]*tls.Certificate
	mu     sync.RWMutex
}

// LoadCA reads the CA certificate and key from disk.
func LoadCA(certFile, keyFile string) (*CertManager, error) {
	return LoadCAWithCRLURL(certFile, keyFile, "")
}

func LoadCAWithCRLURL(certFile, keyFile, crlURL string) (*CertManager, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %q: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read CA key %q: %w", keyFile, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block found in %q", certFile)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block found in %q", keyFile)
	}

	var caKey crypto.Signer
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		k, e := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if e != nil {
			return nil, fmt.Errorf("parse PKCS1 RSA key: %w", e)
		}
		caKey = k
	case "EC PRIVATE KEY":
		k, e := x509.ParseECPrivateKey(keyBlock.Bytes)
		if e != nil {
			return nil, fmt.Errorf("parse EC key: %w", e)
		}
		caKey = k
	case "PRIVATE KEY":
		k, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if e != nil {
			return nil, fmt.Errorf("parse PKCS8 key: %w", e)
		}
		var ok bool
		caKey, ok = k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported PKCS8 key type %T", k)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM key type %q", keyBlock.Type)
	}

	return &CertManager{
		caCert: caCert,
		caKey:  caKey,
		crlURL: strings.TrimSpace(crlURL),
		cache:  make(map[string]*tls.Certificate),
	}, nil
}

// GetCert returns a leaf TLS certificate for the given host (cached).
func (cm *CertManager) GetCert(host string) (*tls.Certificate, error) {
	domain := stripPort(host)

	cm.mu.RLock()
	if cert, ok := cm.cache[domain]; ok {
		cm.mu.RUnlock()
		return cert, nil
	}
	cm.mu.RUnlock()

	cert, err := cm.generateCert(domain)
	if err != nil {
		return nil, err
	}

	cm.mu.Lock()
	cm.cache[domain] = cert
	cm.mu.Unlock()
	return cert, nil
}

// generateCert creates a fresh leaf certificate signed by the CA.
func (cm *CertManager) generateCert(domain string) (*tls.Certificate, error) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"eGatefilter"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if cm.crlURL != "" {
		template.CRLDistributionPoints = []string{cm.crlURL}
	}
	if ip := net.ParseIP(strings.Trim(domain, "[]")); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &leafKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign cert for %q: %w", domain, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  leafKey,
	}
	return tlsCert, nil
}

// TLSServerConfig builds a tls.Config for intercepting client TLS with a generated cert.
func (cm *CertManager) TLSServerConfig(host string) (*tls.Config, error) {
	cert, err := cm.GetCert(host)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" {
				return cm.GetCert(hello.ServerName)
			}
			return cert, nil
		},
		NextProtos: []string{"http/1.1"},
	}, nil
}

func (cm *CertManager) EmptyCRL() ([]byte, error) {
	if cm == nil {
		return nil, fmt.Errorf("CA 未加载")
	}
	now := time.Now()
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:  cm.caCert.SignatureAlgorithm,
		RevokedCertificates: []pkix.RevokedCertificate{},
		Number:              big.NewInt(now.Unix()),
		ThisUpdate:          now.Add(-time.Hour),
		NextUpdate:          now.Add(24 * time.Hour),
	}, cm.caCert, cm.caKey)
}

// stripPort removes the ":port" suffix from host.
func stripPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Make sure it is not an IPv6 address without brackets
		if strings.ContainsRune(host[:idx], ':') {
			return host // IPv6 without brackets — return as-is
		}
		return host[:idx]
	}
	return host
}

// tlsDialHost opens a TLS connection to host (host must include port),
// routing through the upstream proxy if configured.
func (p *Proxy) tlsDialHost(host string) (*tls.Conn, error) {
	return p.tlsDialHostWithServerName(host, "")
}

func (p *Proxy) tlsDialHostWithServerName(host, serverName string) (*tls.Conn, error) {
	if serverName == "" {
		serverName = stripPort(host)
	}
	if p.upstream != nil {
		return p.upstream.DialTLS(host, serverName)
	}
	conn, err := tls.Dial("tcp", host, &tls.Config{
		ServerName: serverName,
		NextProtos: []string{"http/1.1"},
	})
	return conn, err
}

// isECKey returns true if the key is an EC private key (used in tests).
func isECKey(k crypto.Signer) bool {
	_, ok := k.(*ecdsa.PrivateKey)
	return ok
}
