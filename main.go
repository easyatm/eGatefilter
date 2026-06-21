package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
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

	ca, err := LoadCA(cfg.CA.Cert, cfg.CA.Key)
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

	if cfg.Listen.HTTP != "" {
		started++
		go func() {
			log.Printf("HTTP proxy on %s", cfg.Listen.HTTP)
			if err := p.StartHTTP(cfg.Listen.HTTP); err != nil {
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

	if cfg.GUI.Enabled {
		started++
		go func() {
			log.Printf("GUI on %s", cfg.GUI.Listen)
			if err := p.StartGUI(cfg.GUI.Listen); err != nil {
				log.Fatalf("GUI: %v", err)
			}
		}()
	}

	if started == 0 {
		log.Fatal("no listeners configured — set listen.http and/or listen.socks5 in config.json")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}
