package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the top-level configuration structure.
type Config struct {
	Listen struct {
		HTTP   string `json:"http"`
		SOCKS5 string `json:"socks5"`
	} `json:"listen"`
	CA struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"ca"`
	// CacheDir is the root directory for response caching.
	// Set to "" to disable caching.
	CacheDir string          `json:"cache_dir"`
	Capture  CaptureConfig   `json:"capture"`
	GUI      GUIConfig       `json:"gui"`
	Upstream *UpstreamConfig `json:"upstream,omitempty"`
	Rules    []RuleConfig    `json:"rules"`
}

// CaptureConfig 控制抓包数据库与包文文件保存位置。
type CaptureConfig struct {
	Enabled bool   `json:"enabled"`
	DBPath  string `json:"db_path"`
	BodyDir string `json:"body_dir"`
}

// GUIConfig 控制内置前端 GUI 与 API 服务。
type GUIConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
	DistDir string `json:"dist_dir"`
}

// RuleConfig is the configuration for a single rule.
type RuleConfig struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	// action: block | redirect | filter | passthrough
	Action  string           `json:"action"`
	Target  *RedirectTarget  `json:"target,omitempty"`
	Paths   []string         `json:"paths,omitempty"`
	Content []ContentRule    `json:"content,omitempty"`
	File    []FileRuleConfig `json:"file,omitempty"`
}

// RedirectTarget specifies where to redirect connections.
type RedirectTarget struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// ContentRule is a single content replacement rule.
// Paths is optional URL path wildcard list (e.g. "/index.html", "/i18n/*").
type ContentRule struct {
	Match   string   `json:"match"`
	Replace string   `json:"replace"`
	Regex   bool     `json:"regex"`
	Paths   []string `json:"paths,omitempty"`
}

// FileRuleConfig replaces whole response files by local files for filter action.
// Match is URL path wildcard (e.g. "/logo.png", "/i18n/*").
// Local can be:
//   - empty: auto map to "filter/{domain}/{request_path}"
//   - a file path
//   - a wildcard path using "*" captures from Match
type FileRuleConfig struct {
	Match string `json:"match"`
	Local string `json:"local,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(stripComments(data), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// Apply defaults
	if cfg.Listen.HTTP == "" && cfg.Listen.SOCKS5 == "" {
		cfg.Listen.HTTP = ":8080"
		cfg.Listen.SOCKS5 = ":1080"
	}
	if cfg.CA.Cert == "" {
		cfg.CA.Cert = "rootCA/rootCA.crt"
	}
	if cfg.CA.Key == "" {
		cfg.CA.Key = "rootCA/rootCA.key"
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = "cache"
	}
	if cfg.Capture.DBPath == "" {
		cfg.Capture.DBPath = "capture/capture.sqlite"
	}
	if cfg.Capture.BodyDir == "" {
		cfg.Capture.BodyDir = "capture/bodies"
	}
	if cfg.GUI.Listen == "" {
		cfg.GUI.Listen = ":8090"
	}
	if cfg.GUI.DistDir == "" {
		cfg.GUI.DistDir = "web/dist"
	}
	return &cfg, nil
}

// stripComments removes // line comments and /* block comments */ from JSON-like
// data, leaving string literal contents untouched.
// This allows config.json to use comments freely.
func stripComments(src []byte) []byte {
	out := make([]byte, 0, len(src))
	i := 0
	for i < len(src) {
		// ── string literal ───────────────────────────────────────────────────
		if src[i] == '"' {
			out = append(out, src[i])
			i++
			for i < len(src) {
				c := src[i]
				out = append(out, c)
				i++
				if c == '\\' && i < len(src) {
					// escaped character — copy verbatim and skip
					out = append(out, src[i])
					i++
				} else if c == '"' {
					break
				}
			}
			continue
		}

		// ── line comment: // ... \n ───────────────────────────────────────────
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '/' {
			i += 2
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}

		// ── block comment: /* ... */ ──────────────────────────────────────────
		if i+1 < len(src) && src[i] == '/' && src[i+1] == '*' {
			i += 2
			for i+1 < len(src) {
				if src[i] == '*' && src[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		out = append(out, src[i])
		i++
	}
	return out
}
