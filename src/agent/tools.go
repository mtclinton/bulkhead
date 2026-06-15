// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Tool is one capability the agent may invoke. Validate gates the arg before any side effect;
// Run performs it and returns a human/model-readable observation. A tool NEVER touches a BPF
// map or the approve.sock — the egress tool just connect()s (and is gated by the kernel E2
// hook), and the escalation tools exec the existing audited, identity-attested collector verbs.
type Tool struct {
	Validate func(arg string) error
	Run      func(ctx context.Context, arg string) (string, error)
}

const fetchBodyCap = 8 << 10

// collectorBin is the broker/enforce CLI the agent shells out to. Absolute path so it does not
// depend on the jail's PATH. A var so tests can shadow it.
var collectorBin = "/usr/bin/bulkhead-collector"

var validClasses = map[string]bool{"loopback": true, "linklocal": true, "private": true, "public": true, "other": true}

func validClassList(arg string) error {
	if arg == "" {
		return errors.New("empty class list")
	}
	for _, c := range strings.Split(arg, ",") {
		if !validClasses[strings.TrimSpace(c)] {
			return fmt.Errorf("unknown egress class %q", c)
		}
	}
	return nil
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// fetchVia performs the E2/egress-proxy-gated GET shared by the legacy fetch tool and the
// ADR-0036 quarantine interpreter. The (capped) body is copied into sink — io.Discard for the
// legacy loop (the model only ever gets the metadata observation), or planexec's buffer for the
// quarantine (the bytes go to the value store, never to the planner). A DENY/transport failure is
// returned as a structured observation, never a fatal error, so security never depends on it.
func fetchVia(ctx context.Context, arg string, sink io.Writer) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, arg, nil)
	if err != nil {
		return "", err
	}
	hc := egressClient(8 * time.Second) // tunnels via the host egress proxy in the jail
	resp, err := hc.Do(req)
	if err != nil {
		// EPERM = the in-kernel E2 class gate; errEgressDenied = the host egress proxy.
		if errors.Is(err, syscall.EPERM) || errors.Is(err, errEgressDenied) {
			return fmt.Sprintf("DENIED: egress to %s blocked by the egress policy; you may request_egress public to ask the operator", hostOf(arg)), nil
		}
		return fmt.Sprintf("ERROR: fetch %s failed: %v", hostOf(arg), err), nil
	}
	defer resp.Body.Close()
	n, _ := io.Copy(sink, io.LimitReader(resp.Body, fetchBodyCap))
	return fmt.Sprintf("OK: fetch %s -> HTTP %d (%d bytes)", hostOf(arg), resp.StatusCode, n), nil
}

// toolRegistry is the agent's fixed, allowlisted tool set.
func toolRegistry() map[string]Tool {
	return map[string]Tool{
		// fetch: the E2-GATED egress tool. A non-loopback host needs the `public` class; the
		// default manifest is loopback,other, so once E2 is armed connect() returns EPERM and
		// the tool surfaces a structured DENIED observation (so the model can decide to escalate).
		"fetch": {
			Validate: func(arg string) error {
				u, err := url.Parse(arg)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					return errors.New("expected an http(s) URL")
				}
				return nil
			},
			// The legacy loop DISCARDS the body (sink = io.Discard): the model gets only metadata,
			// never the untrusted bytes. The ADR-0036 quarantine path captures the body into the
			// interpreter's value store via fetchVia with a real sink — see planexec.fetchCapture.
			Run: func(ctx context.Context, arg string) (string, error) {
				return fetchVia(ctx, arg, io.Discard)
			},
		},
		// request_egress: ask the TCB broker to WIDEN this agent's egress (ADR-0009 EXPAND).
		// Blocks for a uid-0 operator; on DENY the agent cannot proceed to a successful fetch.
		// Disabled for a DELEGATED child (BULKHEAD_AGENT_NO_EXPAND, ADR-0015): a delegated subtree
		// is hard-capped by its delegation root's mask, so it can never climb past its parent even
		// with an operator approval — escalation is pushed up to operator-launched (root) agents.
		"request_egress": {
			Validate: validClassList,
			Run: func(ctx context.Context, arg string) (string, error) {
				if os.Getenv("BULKHEAD_AGENT_NO_EXPAND") != "" {
					return "ERROR: a delegated child cannot widen its own egress; its ceiling is fixed at delegation (ask via a parent-launched agent)", nil
				}
				return runCollector(ctx, "expand", arg)
			},
		},
		// delegate: spawn a NARROWED child jail (child = parent ∩ requested). Off by default;
		// a deployment opts in via BULKHEAD_AGENT_ALLOW_DELEGATE.
		"delegate": {
			Validate: func(arg string) error {
				f := strings.Fields(arg)
				if len(f) < 2 {
					return errors.New("usage: delegate <suffix> <classes> [task...]")
				}
				return validClassList(f[1])
			},
			Run: func(ctx context.Context, arg string) (string, error) {
				if os.Getenv("BULKHEAD_AGENT_ALLOW_DELEGATE") == "" {
					return "ERROR: delegation is disabled for this agent", nil
				}
				f := strings.Fields(arg)
				args := []string{"delegate", f[0], f[1]}
				if len(f) > 2 {
					// Pass the child task as a SINGLE argv element so exec never re-splits it; the
					// broker validates it and plumbs it through an injection-safe credential channel.
					args = append(args, strings.Join(f[2:], " "))
				}
				return runCollector(ctx, args...)
			},
		},
	}
}

// runCollector execs an EXISTING audited broker verb. The agent is non-root + outside the TCB;
// the broker kernel-attests the agent's cgroup (SO_PEERPIDFD), so the agent supplies only a
// forgeable-free class/op string. A non-zero exit means the gate DENIED the request.
func runCollector(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, collectorBin, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return "ESCALATION DENIED: " + s, nil
	}
	return "escalation OK: " + s, nil
}
