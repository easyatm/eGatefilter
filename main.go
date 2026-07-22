package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Proxy holds the shared state for all proxy servers.
type Proxy struct {
	config   *Config
	ca       *CertManager
	rules    *RuleEngine
	upstream *UpstreamDialer // nil means direct connections
	capture  *CaptureManager
}

func main() {
	configFile := flag.String("c", "config.json", "path to config file")
	flag.Parse()

	cfg, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ca, err := LoadCAWithCRLURL(cfg.CA.Cert, cfg.CA.Key, cfg.CA.CRLURL)
	if err != nil {
		log.Fatalf("CA: %v", err)
	}

	upstream, err := NewUpstreamDialer(cfg.Upstream)
	if err != nil {
		log.Fatalf("upstream proxy: %v", err)
	}
	if upstream != nil {
		switch cfg.Upstream.Type {
		case "socks5":
			log.Printf("upstream: SOCKS5 %s", cfg.Upstream.Socks5Addr)
		case "pac":
			src := cfg.Upstream.PACFile
			if src == "" {
				src = cfg.Upstream.PACURL
			}
			log.Printf("upstream: PAC %s", src)
		}
	}

	capture, err := NewCaptureManager(cfg.Capture)
	if err != nil {
		log.Fatalf("capture: %v", err)
	}
	defer capture.Close()
	if capture != nil {
		log.Printf("capture: SQLite %s, bodies %s", cfg.Capture.DBPath, cfg.Capture.BodyDir)
	}

	p := &Proxy{
		config:   cfg,
		ca:       ca,
		rules:    NewRuleEngine(cfg.Rules),
		upstream: upstream,
		capture:  capture,
	}

	started := 0
	hub := NewCaptureHub()
	if capture != nil {
		capture.SetHub(hub)
	}
	guiHandler := corsMiddleware(p.GUIMux(hub))

	// 如果配置了 mixed 监听，启动混合协议侦听
	if cfg.Listen.Mixed != "" {
		started++
		go func() {
			log.Printf("Mixed listener (SOCKS5 + HTTP/HTTPS Proxy + GUI) on %s", cfg.Listen.Mixed)
			rawListener, err := net.Listen("tcp", cfg.Listen.Mixed)
			if err != nil {
				log.Fatalf("mixed listener bind: %v", err)
			}
			ml := newMixedListener(rawListener)
			defer ml.Close()

			// 启动虚拟 SOCKS5 代理
			go func() {
				socksListener := ml.SOCKSListener()
				log.Printf("Mixed SOCKS5 server running...")
				for {
					conn, err := socksListener.Accept()
					if err != nil {
						return
					}
					go p.handleSOCKS5(conn)
				}
			}()

			// 启动虚拟 HTTP/GUI 服务
			httpListener := ml.HTTPListener()
			log.Printf("Mixed HTTP/GUI server running...")
			server := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					p.handleHTTP(w, r, guiHandler)
				}),
				TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
			}
			if err := server.Serve(httpListener); err != nil {
				log.Printf("mixed http server: %v", err)
			}
		}()
	}

	if cfg.Listen.HTTP != "" {
		started++
		go func() {
			log.Printf("HTTP proxy on %s", cfg.Listen.HTTP)
			server := &http.Server{
				Addr: cfg.Listen.HTTP,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					p.handleHTTP(w, r, guiHandler)
				}),
				TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
			}
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("HTTP proxy: %v", err)
			}
		}()
	}

	if cfg.Listen.SOCKS5 != "" {
		started++
		go func() {
			log.Printf("SOCKS5 proxy on %s", cfg.Listen.SOCKS5)
			if err := p.StartSOCKS5(cfg.Listen.SOCKS5); err != nil {
				log.Fatalf("SOCKS5 proxy: %v", err)
			}
		}()
	}

	if cfg.GUI.Enabled && cfg.GUI.Listen != "" {
		started++
		go func() {
			log.Printf("Standalone GUI on %s", cfg.GUI.Listen)
			server := &http.Server{
				Addr:              cfg.GUI.Listen,
				Handler:           guiHandler,
				ReadHeaderTimeout: 10 * time.Second,
			}
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("GUI: %v", err)
			}
		}()
	}

	if started == 0 {
		log.Fatal("no listeners configured — set listen.mixed, listen.http or listen.socks5 in config.json")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}
