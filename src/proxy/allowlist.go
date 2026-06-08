//go:build linux

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Allowlist is the ADVISORY destination policy (ADR-0034). With no content inspection
// yet (increment 1), the proxy enforces it as the destination allow rule, but the
// BOUNDARY is structural (the no-route netns) — this list only decides which destinations
// the single mediated path will dial. Patterns, one per line:
//
//	*               allow every destination (explicit opt-out of allowlisting)
//	api.host.com    exact host match
//	.example.com    example.com and any subdomain
//	10.0.0.0/8      CIDR (matched when the request is an IP literal)
//	1.2.3.4         exact IP literal
//
// '#' starts a comment. An empty or missing list is fail-closed (deny all).
type Allowlist struct {
	all    bool
	exact  map[string]bool
	suffix []string // ".example.com"
	cidrs  []*net.IPNet
}

func LoadAllowlist(path string) (*Allowlist, error) {
	a := &Allowlist{exact: map[string]bool{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return a, nil // fail-closed (deny all); surfaced loudly via describe()
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		switch {
		case line == "*":
			a.all = true
		case strings.Contains(line, "/"):
			_, n, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("bad CIDR %q: %w", line, err)
			}
			a.cidrs = append(a.cidrs, n)
		case strings.HasPrefix(line, "."):
			a.suffix = append(a.suffix, strings.ToLower(line))
		default:
			a.exact[strings.ToLower(line)] = true
		}
	}
	return a, sc.Err()
}

// Allows reports whether host (a validated DNS name or IP literal) is permitted.
func (a *Allowlist) Allows(host string) bool {
	if a.all {
		return true
	}
	h := strings.ToLower(host)
	if a.exact[h] {
		return true
	}
	for _, s := range a.suffix {
		// ".example.com" allows "example.com" itself and any "*.example.com".
		if h == s[1:] || strings.HasSuffix(h, s) {
			return true
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range a.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
		// an exact IP entry is stored in a.exact and matched above
	}
	return false
}

func (a *Allowlist) describe() string {
	if a.all {
		return "allowlist: * (all destinations permitted — structural confinement is the boundary)"
	}
	if len(a.exact)+len(a.suffix)+len(a.cidrs) == 0 {
		return "allowlist: EMPTY — fail-closed, all egress denied"
	}
	return fmt.Sprintf("allowlist: %d exact, %d suffix, %d cidr", len(a.exact), len(a.suffix), len(a.cidrs))
}
