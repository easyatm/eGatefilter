package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/robertkrimen/otto"
)

// PACEvaluator loads a PAC script and evaluates FindProxyForURL per request.
// Thread-safe: uses a mutex around the single JS VM.
type PACEvaluator struct {
	vm *otto.Otto
	mu sync.Mutex
}

// NewPACEvaluator loads a PAC script from filePath or pacURL (filePath takes priority).
func NewPACEvaluator(filePath, pacURL string) (*PACEvaluator, error) {
	var script []byte
	var err error
	switch {
	case filePath != "":
		script, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read PAC file %q: %w", filePath, err)
		}
	case pacURL != "":
		script, err = httpGet(pacURL)
		if err != nil {
			return nil, fmt.Errorf("fetch PAC URL %q: %w", pacURL, err)
		}
	default:
		return nil, fmt.Errorf("pac_file or pac_url must be set in upstream config")
	}

	vm := otto.New()
	if err := injectPACHelpers(vm); err != nil {
		return nil, err
	}
	if _, err := vm.Run(string(script)); err != nil {
		return nil, fmt.Errorf("eval PAC script: %w", err)
	}
	return &PACEvaluator{vm: vm}, nil
}

// FindProxy calls FindProxyForURL(url, host) and returns the first usable entry.
func (p *PACEvaluator) FindProxy(urlStr, host string) (proxyEntry, error) {
	p.mu.Lock()
	result, err := p.vm.Call("FindProxyForURL", nil, urlStr, host)
	p.mu.Unlock()
	if err != nil {
		return proxyEntry{Type: "DIRECT"}, fmt.Errorf("PAC FindProxyForURL: %w", err)
	}
	return parsePACResult(result.String()), nil
}

// parsePACResult parses a PAC result string like "SOCKS5 1.2.3.4:1080; DIRECT"
// and returns the first directive.
func parsePACResult(s string) proxyEntry {
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "DIRECT":
			return proxyEntry{Type: "DIRECT"}
		case "PROXY", "HTTPS":
			if len(fields) >= 2 {
				return proxyEntry{Type: "PROXY", Addr: fields[1]}
			}
		case "SOCKS5", "SOCKS":
			if len(fields) >= 2 {
				return proxyEntry{Type: "SOCKS5", Addr: fields[1]}
			}
		}
	}
	return proxyEntry{Type: "DIRECT"}
}

// httpGet fetches a URL and returns the body.
func httpGet(url string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// ── PAC helper functions ──────────────────────────────────────────────────────

// injectPACHelpers registers the standard PAC built-in functions into vm.
// Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file
func injectPACHelpers(vm *otto.Otto) error {
	fns := map[string]func(otto.FunctionCall) otto.Value{

		// isPlainHostName(host) — true when host contains no dots
		"isPlainHostName": func(c otto.FunctionCall) otto.Value {
			v, _ := vm.ToValue(!strings.Contains(c.Argument(0).String(), "."))
			return v
		},

		// dnsDomainIs(host, domain) — true when host ends with domain
		"dnsDomainIs": func(c otto.FunctionCall) otto.Value {
			v, _ := vm.ToValue(strings.HasSuffix(c.Argument(0).String(), c.Argument(1).String()))
			return v
		},

		// localHostOrDomainIs(host, hostdom) — host matches or is prefix of hostdom
		"localHostOrDomainIs": func(c otto.FunctionCall) otto.Value {
			host := c.Argument(0).String()
			hostdom := c.Argument(1).String()
			v, _ := vm.ToValue(host == hostdom || strings.HasPrefix(hostdom, host+"."))
			return v
		},

		// isResolvable(host) — true when DNS resolves host
		"isResolvable": func(c otto.FunctionCall) otto.Value {
			addrs, err := net.LookupHost(c.Argument(0).String())
			v, _ := vm.ToValue(err == nil && len(addrs) > 0)
			return v
		},

		// isInNet(host, pattern, mask) — true when host resolves to an IP in pattern/mask
		"isInNet": func(c otto.FunctionCall) otto.Value {
			v, _ := vm.ToValue(pacIsInNet(
				c.Argument(0).String(),
				c.Argument(1).String(),
				c.Argument(2).String(),
			))
			return v
		},

		// dnsResolve(host) — returns the first A record for host, or ""
		"dnsResolve": func(c otto.FunctionCall) otto.Value {
			addrs, err := net.LookupHost(c.Argument(0).String())
			s := ""
			if err == nil && len(addrs) > 0 {
				s = addrs[0]
			}
			v, _ := vm.ToValue(s)
			return v
		},

		// myIpAddress() — returns the machine's primary non-loopback IPv4
		"myIpAddress": func(_ otto.FunctionCall) otto.Value {
			v, _ := vm.ToValue(primaryLocalIP())
			return v
		},

		// dnsDomainLevels(host) — number of dots in host
		"dnsDomainLevels": func(c otto.FunctionCall) otto.Value {
			v, _ := vm.ToValue(strings.Count(c.Argument(0).String(), "."))
			return v
		},

		// shExpMatch(str, shexp) — shell-glob match (* and ?)
		"shExpMatch": func(c otto.FunctionCall) otto.Value {
			v, _ := vm.ToValue(shExpMatch(c.Argument(0).String(), c.Argument(1).String()))
			return v
		},

		// convert_addr(ipaddr) — convert dotted-quad to 32-bit integer
		"convert_addr": func(c otto.FunctionCall) otto.Value {
			ip := net.ParseIP(c.Argument(0).String()).To4()
			var n int64
			if ip != nil {
				n = int64(ip[0])<<24 | int64(ip[1])<<16 | int64(ip[2])<<8 | int64(ip[3])
			}
			v, _ := vm.ToValue(n)
			return v
		},

		// Time-based helpers — stubbed (return false; good enough for host-based routing)
		"weekdayRange": func(_ otto.FunctionCall) otto.Value { v, _ := vm.ToValue(false); return v },
		"dateRange":    func(_ otto.FunctionCall) otto.Value { v, _ := vm.ToValue(false); return v },
		"timeRange":    func(_ otto.FunctionCall) otto.Value { v, _ := vm.ToValue(false); return v },

		// alert — silently discard (some PAC files call it for debug logging)
		"alert": func(_ otto.FunctionCall) otto.Value { return otto.UndefinedValue() },
	}

	for name, fn := range fns {
		if err := vm.Set(name, fn); err != nil {
			return fmt.Errorf("PAC helper %s: %w", name, err)
		}
	}
	return nil
}

// pacIsInNet checks whether host resolves to an IP inside the network defined
// by pattern (network address) and mask (subnet mask, dotted-quad notation).
func pacIsInNet(host, pattern, maskStr string) bool {
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	ip := net.ParseIP(addrs[0]).To4()
	netIP := net.ParseIP(pattern).To4()
	maskIP := net.ParseIP(maskStr).To4()
	if ip == nil || netIP == nil || maskIP == nil {
		return false
	}
	ipNet := &net.IPNet{IP: netIP.Mask(net.IPMask(maskIP)), Mask: net.IPMask(maskIP)}
	return ipNet.Contains(ip)
}

// shExpMatch returns true when str matches the shell-glob pattern.
// Supported wildcards: * (any sequence) and ? (any single character).
func shExpMatch(str, pattern string) bool {
	var re strings.Builder
	re.WriteByte('^')
	for _, ch := range pattern {
		switch ch {
		case '*':
			re.WriteString(".*")
		case '?':
			re.WriteByte('.')
		case '.', '(', ')', '+', '[', ']', '{', '}', '^', '$', '|', '\\':
			re.WriteByte('\\')
			re.WriteRune(ch)
		default:
			re.WriteRune(ch)
		}
	}
	re.WriteByte('$')
	ok, err := regexp.MatchString(re.String(), str)
	return err == nil && ok
}

// primaryLocalIP returns the first non-loopback IPv4 address of the machine.
func primaryLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && !ip.IsLoopback() {
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return "127.0.0.1"
}
