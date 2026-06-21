package main

import (
	"fmt"
	"regexp"
	"strings"
)

// ActionType represents what to do with a matched connection.
type ActionType int

const (
	ActionPassthrough ActionType = iota
	ActionBlock
	ActionRedirect
	ActionFilter
)

func (a ActionType) String() string {
	switch a {
	case ActionPassthrough:
		return "passthrough"
	case ActionBlock:
		return "block"
	case ActionRedirect:
		return "redirect"
	case ActionFilter:
		return "filter"
	}
	return "unknown"
}

// Rule is a compiled rule ready for matching.
type Rule struct {
	Name     string
	patterns []string
	Action   ActionType
	Target   string // "host:port" for redirect
	Paths    []string
	Content  []ContentRule
	File     []FileRuleConfig
}

// RuleEngine matches hosts against ordered rules.
type RuleEngine struct {
	rules []*Rule
}

// NewRuleEngine builds a RuleEngine from configuration.
func NewRuleEngine(configs []RuleConfig) *RuleEngine {
	engine := &RuleEngine{}
	for _, cfg := range configs {
		rule := &Rule{
			Name:     cfg.Name,
			patterns: cfg.Domains,
			Paths:    cfg.Paths,
			Content:  cfg.Content,
			File:     cfg.File,
		}
		switch strings.ToLower(cfg.Action) {
		case "block":
			rule.Action = ActionBlock
		case "redirect":
			rule.Action = ActionRedirect
			if cfg.Target != nil {
				rule.Target = fmt.Sprintf("%s:%d", cfg.Target.Host, cfg.Target.Port)
			}
		case "filter":
			rule.Action = ActionFilter
		default:
			rule.Action = ActionPassthrough
		}
		engine.rules = append(engine.rules, rule)
	}
	return engine
}

// ShouldFilterPath reports whether a URL path should apply filter action for this rule.
// Empty path patterns mean "all paths".
func (r *Rule) ShouldFilterPath(urlPath string) bool {
	if len(r.Paths) == 0 {
		return true
	}
	for _, p := range r.Paths {
		if wildcardMatch(p, urlPath) {
			return true
		}
	}
	return false
}

// Match returns the first rule whose domain pattern matches host.
// host may contain a port suffix (e.g. "example.com:443").
func (e *RuleEngine) Match(host string) *Rule {
	domain := host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		domain = host[:idx]
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	for _, rule := range e.rules {
		for _, pattern := range rule.patterns {
			if matchWildcard(strings.ToLower(pattern), domain) {
				return rule
			}
		}
	}
	return nil
}

// matchWildcard tests whether domain matches pattern.
//
// Supported patterns:
//   - exact match:   "example.com"
//   - wildcard:      "*.example.com"  — matches any single sub-level
//   - global:        "*"              — matches everything
func matchWildcard(pattern, domain string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		// *.example.com matches sub.example.com and a.b.example.com
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(domain, suffix) && len(domain) > len(suffix)
	}
	return false
}

// wildcardMatch supports "*" as a glob wildcard for generic strings.
// Example: "/test*.html", "/i18n/*", "*".
func wildcardMatch(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	re, err := wildcardToRegexp(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// wildcardCaptures returns wildcard captures for pattern/value.
// For pattern "/i18n/*", value "/i18n/en-US.json", captures is ["en-US.json"].
func wildcardCaptures(pattern, value string) ([]string, bool) {
	re, err := wildcardToRegexp(pattern)
	if err != nil {
		return nil, false
	}
	m := re.FindStringSubmatch(value)
	if m == nil {
		return nil, false
	}
	return m[1:], true
}

func wildcardToRegexp(pattern string) (*regexp.Regexp, error) {
	quoted := regexp.QuoteMeta(strings.TrimSpace(pattern))
	quoted = strings.ReplaceAll(quoted, `\*`, `(.*)`)
	return regexp.Compile("^" + quoted + "$")
}
