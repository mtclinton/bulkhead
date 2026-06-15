//go:build linux

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// egress modes (ADR-0034 increment 2): the per-allowlist-entry disposition for a PERMITTED
// destination. The allowlist still decides WHICH destinations the single mediated path dials
// (inc1); the mode decides whether that flow is TLS-terminated + content-inspected or spliced
// opaque. Default is passthrough (compatibility-safe); a host is body-inspected only when its
// entry explicitly says so.
const (
	modeInspect     = "inspect"     // TLS-terminate + content-inspect (the body-exfil guarantee)
	modePassthrough = "passthrough" // opaque inc1 splice; inspection deliberately waived (default)
	modePinned      = "pinned"      // opaque splice, tagged: MITM would BREAK this (cert-pinned/mTLS)
)

func validMode(m string) bool {
	return m == modeInspect || m == modePassthrough || m == modePinned
}

type suffixRule struct {
	suffix string // ".example.com"
	mode   string
}

type cidrRule struct {
	net  *net.IPNet
	mode string
}

// Allowlist is the ADVISORY destination policy (ADR-0034). The BOUNDARY is structural (the
// no-route netns); this list decides which destinations the single mediated path will dial and,
// per inc2, whether each is inspected. One entry per line: "<pattern> [mode]". A bare "*" permits
// every name, "api.host.com" matches that exact host, ".example.com" matches example.com and any
// subdomain, "10.0.0.0/8" is a CIDR (matched when the request is an IP literal), and "1.2.3.4" is
// an exact IP. The optional trailing mode token is inspect|passthrough|pinned (default passthrough).
// '#' starts a comment; an empty or missing list is fail-closed (deny all). Internal address
// classes (loopback/private/link-local/metadata) are denied at dial regardless — see checkDialAddr.
type Allowlist struct {
	all     bool
	allMode string
	exact   map[string]string // host -> mode
	suffix  []suffixRule
	cidrs   []cidrRule
}

func LoadAllowlist(path string) (*Allowlist, error) {
	a := &Allowlist{exact: map[string]string{}, allMode: modePassthrough}
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
		// "<pattern> [mode]" — the optional second field is the inspection disposition.
		fields := strings.Fields(line)
		pat := fields[0]
		mode := modePassthrough
		if len(fields) >= 2 {
			mode = strings.ToLower(fields[1])
			if !validMode(mode) {
				return nil, fmt.Errorf("bad mode %q for %q (want inspect|passthrough|pinned)", fields[1], pat)
			}
		}
		switch {
		case pat == "*":
			a.all = true
			a.allMode = mode
		case strings.Contains(pat, "/"):
			_, n, err := net.ParseCIDR(pat)
			if err != nil {
				return nil, fmt.Errorf("bad CIDR %q: %w", pat, err)
			}
			a.cidrs = append(a.cidrs, cidrRule{n, mode})
		case strings.HasPrefix(pat, "."):
			a.suffix = append(a.suffix, suffixRule{strings.ToLower(pat), mode})
		default:
			a.exact[strings.ToLower(pat)] = mode
		}
	}
	return a, sc.Err()
}

// Allows reports whether host (a validated DNS name or IP literal) is permitted. Behaviour is
// identical to inc1 — the mode tokens do not change WHICH hosts are allowed, only how an allowed
// flow is handled.
func (a *Allowlist) Allows(host string) bool {
	if a.all {
		return true
	}
	h := strings.ToLower(host)
	if _, ok := a.exact[h]; ok {
		return true
	}
	for _, s := range a.suffix {
		// ".example.com" allows "example.com" itself and any "*.example.com".
		if h == s.suffix[1:] || strings.HasSuffix(h, s.suffix) {
			return true
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, c := range a.cidrs {
			if c.net.Contains(ip) {
				return true
			}
		}
		// an exact IP entry is stored in a.exact and matched above
	}
	return false
}

// Mode returns the inspection disposition for a host. It uses the SAME host matching as Allows
// (the destination is parsed once, in readRequest, and never re-interpreted), but resolves the
// most-SPECIFIC matching entry first (exact > suffix > cidr > "*") so a per-host "inspect" wins
// over a "* passthrough" default. A host that matches nothing returns passthrough — Mode is only
// meaningful after Allows returned true, and passthrough is the safe fallback.
func (a *Allowlist) Mode(host string) string {
	h := strings.ToLower(host)
	if m, ok := a.exact[h]; ok {
		return m
	}
	for _, s := range a.suffix {
		if h == s.suffix[1:] || strings.HasSuffix(h, s.suffix) {
			return s.mode
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, c := range a.cidrs {
			if c.net.Contains(ip) {
				return c.mode
			}
		}
	}
	if a.all {
		return a.allMode
	}
	return modePassthrough
}

func (a *Allowlist) describe() string {
	if a.all {
		return fmt.Sprintf("allowlist: * (all NAMES permitted, default mode %s; internal loopback/link-local/private/metadata still denied at dial)", a.allMode)
	}
	if len(a.exact)+len(a.suffix)+len(a.cidrs) == 0 {
		return "allowlist: EMPTY — fail-closed, all egress denied"
	}
	return fmt.Sprintf("allowlist: %d exact, %d suffix, %d cidr", len(a.exact), len(a.suffix), len(a.cidrs))
}
