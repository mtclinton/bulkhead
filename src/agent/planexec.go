// SPDX-License-Identifier: AGPL-3.0-only
package main

// planexec is the deterministic, non-LLM interpreter of the ADR-0036 model-routing quarantine
// (Dual-LLM / CaMeL). It is the reference monitor the model is NOT: it owns control flow, holds
// the typed value store, and is the ONLY thing that touches the privileged tool registry. A
// PLANNING model (P-LLM) emits a STATIC plan over the trusted task only — it never sees fetched
// bytes; planexec executes that plan in committed order and hands untrusted bytes to a QUARANTINED
// reader (Q-LLM, qresponse.go) whose reply is stored as DATA and never parsed as a directive.
//
// The provable property (report #2): untrusted tool output cannot influence control flow, because
// control flow IS the plan, fixed before any untrusted byte is read. The quarantine is STATIC-PLAN
// ONLY (it refuses data-dependent branching by grammar — CaMeL is 0% on the dynamic AgentDyn
// benchmark); it is a user-space control-flow-integrity property layered on ADR-0035's kernel
// resource authorization, NOT itself a kernel reference monitor. A corrupted interpreter voids the
// property, so this stays small, stdlib-only, and fail-closed on any off-grammar plan.
//
// Grammar (one opcode per line, nothing else):
//
//	FETCH <http-url> -> $var              GET a LITERAL url (never a $var — no data-dependent fetch)
//	EXTRACT $src <question> -> $var       quarantined reader answers <question> over the bytes in $src
//	REPORT $var                           terminal; $var (an EXTRACT result) is the answer
//	DELEGATE <suffix> <classes> <task>    terminal; spawn a child — task may be tainted, authority is not
//
// The typed-taint rule the interpreter enforces structurally (the CaMeL property):
//   - A FETCH target must be a literal — an extracted value can never select WHAT is fetched.
//   - DELEGATE's suffix + classes are CONTROL (the child's identity + kernel-enforced authority): they
//     MUST be literals, fixed by the trusted planner. The task is the sole DATA slot — it may be a
//     tainted EXTRACT result ($vData var). So an injection in fetched content can set a delegated
//     child's TASK (data) but NEVER its AUTHORITY (control); the child stays bounded by the plan-fixed
//     classes ∩ parent, enforced by the broker + the kernel E2 manifest (narrow-never-widen).
//   - Slice A confined EXTRACT results to REPORT; inc2 (this) lets a tainted value flow into the
//     DELEGATE task only. A tainted value may NEVER select which opcode runs, whether it runs, or any
//     control-relevant argument. Replanning stays an explicit non-goal.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
)

const maxPlanSteps = 16

type opKind int

const (
	opFetch opKind = iota
	opExtract
	opReport
	opDelegate
)

type planStep struct {
	op       opKind
	url      string // opFetch: literal url
	src      string // opExtract: source var name (a FETCHed body)
	question string // opExtract: literal question
	dst      string // opFetch/opExtract: bound var name
	rep      string // opReport: var name to report
	// opDelegate (inc2): suffix + classes are CONTROL (literal, plan-fixed — child identity +
	// authority); the task is DATA — either a literal or a tainted EXTRACT result (taskVar).
	suffix  string
	classes string
	task    string // literal task (DATA), when taskVar == ""
	taskVar string // var name of a tainted (vData) task, when set
}

type valKind int

const (
	vBody valKind = iota // untrusted fetched bytes
	vData                // a quarantined-reader (Q-LLM) result — DATA, never a directive
)

type qval struct {
	kind  valKind
	bytes []byte // vBody
	text  string // vData
}

// runQuarantine is the ADR-0036 quarantine entry point (selected by BULKHEAD_AGENT_QUARANTINE).
// It asks the PLANNING model for a static plan over the TRUSTED task (the planner never sees
// fetched content), refuses any off-grammar plan fail-closed, then executes it deterministically.
func runQuarantine(ctx context.Context, routerURL, task string, reg map[string]Tool) (string, error) {
	planText, err := chat(ctx, routerURL, []ChatMessage{
		{Role: "system", Content: planPrompt()},
		{Role: "user", Content: "Task: " + task},
	})
	if err != nil {
		return "", fmt.Errorf("planning: %w", err)
	}
	steps, err := parsePlan(planText)
	if err != nil {
		// Fail-closed: a malformed/hostile plan runs NOTHING (better to refuse than mis-execute).
		return "", fmt.Errorf("plan refused: %w", err)
	}
	log.Printf("quarantine: planner committed a %d-step static plan (the planner never sees fetched bytes)", len(steps))
	return runPlan(ctx, routerURL, steps, reg)
}

func planPrompt() string {
	return strings.Join([]string{
		"You are the PLANNING half of a bulkhead quarantine agent. You NEVER see fetched content.",
		"Emit a STATIC plan, ONE opcode per line, and nothing else. Valid opcodes:",
		"  FETCH <http-url> -> $var              -- GET a URL you name explicitly (a literal, never a $var)",
		"  EXTRACT $src <question> -> $var       -- the quarantined reader answers <question> over the bytes in $src",
		"  REPORT $var                           -- finish; $var (an EXTRACT result) is the answer",
		"  DELEGATE <suffix> <classes> <task>    -- finish; spawn a sub-agent. suffix + classes are LITERAL (you",
		"                                           fix the child's identity + egress); <task> may be a literal OR a",
		"                                           $var EXTRACT result (the child's instructions, never its authority)",
		"The plan is fixed before any content is read: you may NOT branch on content, a FETCH target is",
		"always a literal URL, and a child's suffix + classes are always literals you choose. The last line",
		"must be REPORT or DELEGATE. Output nothing but the plan lines.",
	}, "\n")
}

// parsePlan is strict-OUT: every non-blank line must be a valid opcode or the whole plan is
// refused. This is the fail-closed boundary — IF/WHILE/GOTO, a $variable FETCH target, an
// unbound/wrong-kind reference, or anything after REPORT all reject the plan rather than degrade.
func parsePlan(text string) ([]planStep, error) {
	var steps []planStep
	bound := map[string]valKind{}
	reported := false
	fetchValidate := toolRegistry()["fetch"].Validate
	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if reported {
			return nil, fmt.Errorf("line %d: no opcode may follow the terminal REPORT/DELEGATE", n+1)
		}
		if len(steps) >= maxPlanSteps {
			return nil, fmt.Errorf("plan exceeds the %d-step cap", maxPlanSteps)
		}
		verb, rest, _ := strings.Cut(line, " ")
		switch verb {
		case "FETCH":
			lhs, dst, ok := splitArrow(rest)
			if !ok {
				return nil, fmt.Errorf("line %d: FETCH needs '<url> -> $var'", n+1)
			}
			name, err := varName(dst)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n+1, err)
			}
			if _, dup := bound[name]; dup {
				return nil, fmt.Errorf("line %d: $%s already bound", n+1, name)
			}
			url := strings.TrimSpace(lhs)
			if strings.HasPrefix(url, "$") {
				return nil, fmt.Errorf("line %d: FETCH target must be a literal URL, not a variable (no data-dependent fetch in a static plan)", n+1)
			}
			if err := fetchValidate(url); err != nil {
				return nil, fmt.Errorf("line %d: FETCH url: %w", n+1, err)
			}
			bound[name] = vBody
			steps = append(steps, planStep{op: opFetch, url: url, dst: name})
		case "EXTRACT":
			lhs, dst, ok := splitArrow(rest)
			if !ok {
				return nil, fmt.Errorf("line %d: EXTRACT needs '$src <question> -> $var'", n+1)
			}
			dname, err := varName(dst)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n+1, err)
			}
			if _, dup := bound[dname]; dup {
				return nil, fmt.Errorf("line %d: $%s already bound", n+1, dname)
			}
			srcTok, question, _ := strings.Cut(strings.TrimSpace(lhs), " ")
			sname, err := varName(srcTok)
			if err != nil {
				return nil, fmt.Errorf("line %d: EXTRACT source: %w", n+1, err)
			}
			if k, ok := bound[sname]; !ok || k != vBody {
				return nil, fmt.Errorf("line %d: EXTRACT source $%s must be a FETCHed page", n+1, sname)
			}
			if strings.TrimSpace(question) == "" {
				return nil, fmt.Errorf("line %d: EXTRACT needs a question", n+1)
			}
			bound[dname] = vData
			steps = append(steps, planStep{op: opExtract, src: sname, question: strings.TrimSpace(question), dst: dname})
		case "REPORT":
			rname, err := varName(strings.TrimSpace(rest))
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n+1, err)
			}
			// Slice A: an EXTRACT result may ONLY be REPORTed (it can never become a tool arg).
			if k, ok := bound[rname]; !ok || k != vData {
				return nil, fmt.Errorf("line %d: REPORT $%s must be an EXTRACT result (data)", n+1, rname)
			}
			steps = append(steps, planStep{op: opReport, rep: rname})
			reported = true
		case "DELEGATE":
			// DELEGATE <suffix> <classes> <task...>. suffix + classes are CONTROL (literals fixed by
			// the planner); the task is the sole DATA slot (a literal or a tainted $vData var).
			f := strings.Fields(rest)
			if len(f) < 3 {
				return nil, fmt.Errorf("line %d: DELEGATE needs '<suffix> <classes> <task-or-$var>'", n+1)
			}
			suffix, classes := f[0], f[1]
			// The taint boundary: a tainted value may NEVER set the child's identity or authority.
			if strings.HasPrefix(suffix, "$") || strings.HasPrefix(classes, "$") {
				return nil, fmt.Errorf("line %d: DELEGATE suffix and classes must be literals — a tainted/extracted value can never set a child's identity or authority", n+1)
			}
			if !isIdent(suffix) {
				return nil, fmt.Errorf("line %d: DELEGATE suffix %q must be an identifier", n+1, suffix)
			}
			if err := validClassList(classes); err != nil {
				return nil, fmt.Errorf("line %d: DELEGATE classes: %w", n+1, err)
			}
			step := planStep{op: opDelegate, suffix: suffix, classes: classes}
			taskTok := strings.TrimSpace(strings.Join(f[2:], " "))
			if strings.HasPrefix(taskTok, "$") && !strings.ContainsAny(taskTok, " \t") {
				// A lone $var task: the DATA slot may carry a tainted EXTRACT result.
				tname, err := varName(taskTok)
				if err != nil {
					return nil, fmt.Errorf("line %d: DELEGATE task: %w", n+1, err)
				}
				if k, ok := bound[tname]; !ok || k != vData {
					return nil, fmt.Errorf("line %d: DELEGATE task $%s must be an EXTRACT result (data)", n+1, tname)
				}
				step.taskVar = tname
			} else {
				// A literal (plan-fixed, trusted) task.
				step.task = taskTok
			}
			steps = append(steps, step)
			reported = true
		default:
			return nil, fmt.Errorf("line %d: unknown opcode %q (only FETCH/EXTRACT/REPORT/DELEGATE)", n+1, verb)
		}
	}
	if !reported {
		return nil, errors.New("plan must end with REPORT or DELEGATE")
	}
	return steps, nil
}

// runPlan executes a committed static plan. Control flow is the plan, not any model utterance:
// FETCH bytes go ONLY into the value store (never back to the planner), EXTRACT routes those bytes
// through the quarantined no-tools reader and stores its reply as DATA, REPORT returns that data.
func runPlan(ctx context.Context, routerURL string, steps []planStep, reg map[string]Tool) (string, error) {
	store := map[string]qval{}
	for _, s := range steps {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		switch s.op {
		case opFetch:
			// The same deterministic gate the legacy loop uses: the fetch Validate, then the
			// egress-proxy/BPF-LSM-E2 chokepoint inside fetchVia. No model is in this path.
			if err := reg["fetch"].Validate(s.url); err != nil {
				return "", fmt.Errorf("FETCH %s: %w", s.url, err)
			}
			meta, body, err := fetchCapture(ctx, s.url)
			if err != nil {
				return "", fmt.Errorf("FETCH %s: %w", s.url, err)
			}
			log.Printf("quarantine: FETCH %s -> $%s [%s] (%d body bytes held in the store, NEVER shown to the planner)",
				s.url, s.dst, meta, len(body))
			store[s.dst] = qval{kind: vBody, bytes: body}
		case opExtract:
			src := store[s.src] // parse guaranteed this is a vBody
			ans, err := extract(ctx, routerURL, src.bytes, s.question)
			if err != nil {
				return "", fmt.Errorf("EXTRACT $%s: %w", s.src, err)
			}
			log.Printf("quarantine: EXTRACT $%s %q -> $%s (quarantined reader returned %d data bytes; stored as DATA, never parsed as a directive)",
				s.src, s.question, s.dst, len(ans))
			store[s.dst] = qval{kind: vData, text: ans}
		case opReport:
			log.Printf("quarantine: REPORT $%s (terminal)", s.rep)
			return store[s.rep].text, nil
		case opDelegate:
			// The child's identity + authority are PLAN-FIXED (literals the planner chose); only the
			// task is data, and it may be tainted. runDelegate hands the task to the broker as one
			// argv element — the child is born classes ∩ parent (narrow-never-widen, E2-enforced), so
			// a tainted task can direct WHAT the child does but never widen WHAT it is allowed to do.
			task, taint := s.task, "plan-fixed literal"
			if s.taskVar != "" {
				task, taint = store[s.taskVar].text, "TAINTED ($"+s.taskVar+", an extracted value)"
			}
			log.Printf("quarantine: DELEGATE suffix=%s classes=%s (PLAN-FIXED authority) task=<%d bytes, %s>",
				s.suffix, s.classes, len(task), taint)
			obs, err := runDelegate(ctx, s.suffix, s.classes, task)
			if err != nil {
				return "", fmt.Errorf("DELEGATE %s: %w", s.suffix, err)
			}
			log.Printf("quarantine: DELEGATE %s -> %s (terminal)", s.suffix, truncate(obs, 200))
			return obs, nil
		}
	}
	return "", errors.New("plan completed without REPORT")
}

// fetchCapture performs the SAME egress-proxy/E2-gated GET as the fetch tool, but RETAINS the
// (capped) body for the interpreter's value store. The body reaches ONLY planexec — never the
// planner's message history — which is the whole structural point (vs the legacy OBSERVATION-append).
func fetchCapture(ctx context.Context, url string) (string, []byte, error) {
	var buf bytes.Buffer
	meta, err := fetchVia(ctx, url, &buf)
	return meta, buf.Bytes(), err
}

func splitArrow(s string) (lhs, rhs string, ok bool) {
	i := strings.Index(s, "->")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:]), true
}

func varName(tok string) (string, error) {
	if !strings.HasPrefix(tok, "$") {
		return "", fmt.Errorf("expected a $variable, got %q", tok)
	}
	name := tok[1:]
	if name == "" || !isIdent(name) {
		return "", fmt.Errorf("bad variable %q", tok)
	}
	return name, nil
}

func isIdent(s string) bool {
	for _, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
