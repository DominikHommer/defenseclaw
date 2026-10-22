// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Owner decision 2026-10-20: a standalone managed hook follows the fail mode
// its administrator-owned runtime records. In fail mode open a call
// DefenseClaw cannot check because the gateway is down, did not answer or
// gave an unusable answer goes ahead and is logged fail-open, as on a
// per-user install. Refusals that are not an outage stay closed: a gateway
// peer DefenseClaw cannot verify, an invalid managed runtime and a missing
// token, an authentication refusal (401/403, also after the 401 retries) and
// a local event binding or contract mismatch. Strict availability still
// closes it.
func TestStandaloneManagedHookFollowsTheAdministratorsOpenFailMode(t *testing.T) {
	original := hookAuthRetryDelay
	hookAuthRetryDelay = time.Millisecond
	t.Cleanup(func() { hookAuthRetryDelay = original })
	standaloneOpen := func(opts *Options) {
		managedCodex(opts)
		opts.ExplainUnenrolledAccount = true
		opts.FailMode = "open"
	}
	for _, tc := range []struct {
		name    string
		rt      *stubRT
		mutate  func(*Options)
		blocked bool
	}{
		// Bounded review P1: only an outage ManagedOutageFailsOpen names
		// (not running, restarting, no answer) is open; a transport error
		// that is not one, an error status and an unusable answer are closed.
		{name: "gateway unreachable", rt: &stubRT{err: errors.New("offline")}, blocked: true},
		{name: "gateway 5xx", rt: &stubRT{status: 503, body: "unavailable"}, blocked: true},
		{name: "malformed answer", rt: ok("not-json"), blocked: true},
		{name: "oversized input", rt: ok(`{"action":"allow"}`), blocked: true,
			mutate: func(o *Options) { o.MaxBody = 8 }},
		{name: "gateway not running", rt: &stubRT{err: fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)}},
		{name: "unverified gateway peer", rt: &stubRT{err: errManagedGatewayPeerUnverified}, blocked: true},
		{name: "invalid managed runtime", rt: ok(`{"action":"allow"}`), blocked: true,
			mutate: func(o *Options) { o.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid" }},
		{name: "strict availability", rt: &stubRT{err: errors.New("offline")}, blocked: true,
			mutate: func(o *Options) { o.StrictAvailability = true }},
		{name: "gateway 401 after retries", rt: &stubRT{status: 401, body: `{"error":"unauthorized"}`}, blocked: true},
		{name: "gateway 403", rt: &stubRT{status: 403, body: `{"error":"forbidden"}`}, blocked: true},
		{name: "codex contract missing", rt: ok(`{"action":"allow"}`), blocked: true,
			mutate: func(o *Options) { o.HookContractID = "" }},
		{name: "codex event mismatch", rt: ok(`{"action":"allow"}`), blocked: true,
			mutate: func(o *Options) { o.Stdin = strings.NewReader(`{"hook_event_name":"PostToolUse"}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "codex", tc.rt, func(o *Options) {
				standaloneOpen(o)
				if tc.mutate != nil {
					tc.mutate(o)
				}
			})
			if blocked(result) != tc.blocked {
				t.Fatalf("blocked = %v, want %v: code=%d stdout=%q stderr=%q", blocked(result), tc.blocked, result.code, result.stdout, result.stderr)
			}
		})
	}
	// The same hook in fail mode closed, the default, blocks an outage.
	closed := run(t, "codex", &stubRT{err: errors.New("offline")}, func(o *Options) {
		standaloneOpen(o)
		o.FailMode = "closed"
	})
	if !blocked(closed) {
		t.Fatalf("closed standalone hook allowed an outage: code=%d stdout=%q", closed.code, closed.stdout)
	}
}

// A standalone Hermes hook in fail mode open lets a tool call through on an
// outage instead of the managed block directive; closed blocks it.
func TestStandaloneManagedHermesFollowsTheAdministratorsFailMode(t *testing.T) {
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for mode, wantBlock := range map[string]bool{"open": false, "closed": true} {
		result := run(t, "hermes", &stubRT{err: notRunning}, func(o *Options) {
			o.Event = "pre_tool_call"
			o.FailMode = mode
			o.ManagedEnterprise = true
			o.ExplainUnenrolledAccount = true
		})
		if got := blocked(result); got != wantBlock {
			t.Fatalf("fail mode %s: blocked = %v, want %v: stdout=%q stderr=%q", mode, got, wantBlock, result.stdout, result.stderr)
		}
	}
}

// GAP-0346: a managed standalone GitHub Copilot hook follows the
// administrator's fail mode when its gateway service is not running: unset
// and closed block the tool call and the permission request with Copilot's
// native deny, open allows them. An unapproved hook the foreign-hook guard
// found, and an invalid managed runtime, block in fail mode open too.
func TestStandaloneManagedCopilotFollowsTheAdministratorsFailMode(t *testing.T) {
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for _, event := range []string{"preToolUse", "permissionRequest"} {
		for _, tc := range []struct {
			mode    string
			failure string
			blocked bool
		}{
			{mode: "", blocked: true},
			{mode: "open"},
			{mode: "closed", blocked: true},
			{mode: "open", failure: ForeignHookBlockedReasonPrefix + " your organization blocks copilot hooks it has not approved", blocked: true},
			{mode: "open", failure: "enterprise_managed_runtime_state_invalid", blocked: true},
		} {
			result := run(t, "copilot", &stubRT{err: notRunning}, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.Event = event
				o.FailMode = tc.mode
				o.ManagedRuntimeFailure = tc.failure
				o.Stdin = strings.NewReader(`{"toolName":"bash","toolArgs":"{\"command\":\"echo ok\"}"}`)
			})
			if got := blocked(result); got != tc.blocked {
				t.Fatalf("%s, fail mode %q, runtime failure %q: blocked = %v, want %v: stdout=%q stderr=%q",
					event, tc.mode, tc.failure, got, tc.blocked, result.stdout, result.stderr)
			}
			if !tc.blocked && !strings.Contains(result.stderr, "allowing") {
				t.Fatalf("%s: an open outage must say the call is allowed: stderr=%q", event, result.stderr)
			}
		}
	}
}

// 1.0.4 review (loop round 3 of G-hooks-upg): the docs promised that a
// managed standalone Copilot hook blocks during a gateway outage, but one
// whose administrator chose open lets the call run (managedCopilotOpen).
// The outage blocks only in the effective mode closed or with strict
// availability; this pins the behavior and that the docs say so. hookexec
// runs the managed Copilot hook on Windows only: the Linux and macOS
// managed hook is copilot-hook.sh, which blocks in every fail mode
// (connector.TestManagedUnixCopilotOutageBlocksInEveryFailModeAsDocumented).
func TestManagedCopilotOutageBlockingDocsFollowTheFailMode(t *testing.T) {
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for _, tc := range []struct {
		mode    string
		strict  bool
		blocked bool
	}{
		{mode: "closed", blocked: true},
		{mode: "open", strict: true, blocked: true},
		{mode: "open"},
	} {
		result := run(t, "copilot", &stubRT{err: notRunning}, func(o *Options) {
			managedCodex(o)
			o.ExplainUnenrolledAccount = true
			o.Event = "preToolUse"
			o.FailMode = tc.mode
			o.StrictAvailability = tc.strict
			o.Stdin = strings.NewReader(`{"toolName":"bash","toolArgs":"{\"command\":\"echo ok\"}"}`)
		})
		if got := blocked(result); got != tc.blocked {
			t.Fatalf("fail mode %q, strict %v: blocked = %v, want %v: stdout=%q", tc.mode, tc.strict, got, tc.blocked, result.stdout)
		}
	}
	docs := filepath.Join("..", "..", "..", "..", "docs-site", "content", "docs")
	for _, doc := range []struct {
		path      string
		want      []string
		forbidden []string
	}{
		{filepath.Join(docs, "reference", "fail-modes.mdx"), []string{
			"on Windows in the effective mode `closed`, the default, or with strict availability) |",
			"On Windows it blocks them only in the effective mode `closed` (the default) or with [strict availability](#strict-availability); with the administrator's `hook_fail_mode: open` it lets the call run",
		}, []string{
			"No (managed standalone: blocks `preToolUse` and `permissionRequest` while the gateway is down) |",
			"Only an administrator-managed standalone Copilot hook blocks",
		}},
		{filepath.Join(docs, "connectors", "copilot.mdx"), []string{
			"On Windows it denies them in the effective mode `closed` (the default) or with [strict availability](/docs/reference/fail-modes#strict-availability), and the administrator's `hook_fail_mode: open` lets them run.",
		}, []string{
			"the administrator-owned hook is stricter: it denies",
		}},
		{filepath.Join(docs, "connectors", "capability-matrix.mdx"), []string{
			"A managed hook lets a call run during a gateway outage only when the administrator set `hook_fail_mode: open`, and never with strict availability.",
		}, []string{
			"a managed hook never fails open on a gateway outage",
		}},
		{filepath.Join(docs, "enterprise", "troubleshooting.mdx"), []string{
			"with the administrator's `hook_fail_mode: open`, an outage lets it run.",
		}, []string{
			"stops. Every call checked while the gateway is down is blocked.",
		}},
	} {
		data, err := os.ReadFile(doc.path)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		for _, want := range doc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s: missing %q", doc.path, want)
			}
		}
		for _, forbidden := range doc.forbidden {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s still promises outage blocking whatever the fail mode: %q", doc.path, forbidden)
			}
		}
	}
}

// 1.0.4 review (loop round 4 of G-hooks-upg): the fail-modes page, the
// enterprise overview, troubleshooting, the threat model and the source of
// truth said DEFENSECLAW_FAIL_MODE=closed is honored on a managed host when
// it tightens. No hook reads it (the native hook resolves the administrator's
// mode before hookexec runs; TestManagedWindowsHookIgnoresTheEnvironmentFailMode
// pins that on Windows), so an open managed Copilot hook still lets a call
// run during an outage whatever the environment says. Only the installed
// mode and strict availability decide. This pins that behavior and the docs.
func TestManagedFailModeDocsDoNotPromiseAnEnvironmentOverride(t *testing.T) {
	t.Setenv("DEFENSECLAW_FAIL_MODE", "closed")
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for _, tc := range []struct {
		mode    string
		strict  bool
		blocked bool
	}{
		{mode: "open"},
		{mode: "open", strict: true, blocked: true},
		{mode: "closed", blocked: true},
	} {
		result := run(t, "copilot", &stubRT{err: notRunning}, func(o *Options) {
			managedCodex(o)
			o.ExplainUnenrolledAccount = true
			o.Event = "preToolUse"
			o.FailMode = tc.mode
			o.StrictAvailability = tc.strict
			o.Stdin = strings.NewReader(`{"toolName":"bash","toolArgs":"{\"command\":\"echo ok\"}"}`)
		})
		if got := blocked(result); got != tc.blocked {
			t.Fatalf("installed mode %q, strict %v, DEFENSECLAW_FAIL_MODE=closed: blocked = %v, want %v: stdout=%q",
				tc.mode, tc.strict, got, tc.blocked, result.stdout)
		}
	}
	docs := filepath.Join("..", "..", "..", "..", "docs-site", "content", "docs")
	for _, doc := range []struct {
		path      string
		want      []string
		forbidden []string
	}{
		{filepath.Join(docs, "reference", "fail-modes.mdx"), []string{
			"`DEFENSECLAW_FAIL_MODE` in the agent's environment does not change it: `closed` there does not close a hook the administrator set to `open`, so an outage still lets the call run (on Linux and macOS not through the Amp and OpenCode plugins or the GitHub Copilot CLI hook, which block it in every fail mode).",
			"`DEFENSECLAW_STRICT_AVAILABILITY=1`, which a managed hook honors because it can only close.",
		}, []string{
			"both variables are *tighten-only*",
			"a value that makes hooks stricter is honored",
		}},
		{filepath.Join(docs, "enterprise", "troubleshooting.mdx"), []string{
			"No managed standalone hook reads `DEFENSECLAW_FAIL_MODE` (the Antigravity, Devin, Hermes and Kiro shell hooks of a Secure Client deployment still take it as a full override)",
		}, []string{
			"(`DEFENSECLAW_FAIL_MODE`, `DEFENSECLAW_STRICT_AVAILABILITY` and `DEFENSECLAW_HOOK_MAX_BODY` are `tighten_only`: honored only when stricter)",
		}},
		{filepath.Join(docs, "enterprise", "index.mdx"), []string{
			"`DEFENSECLAW_FAIL_MODE` is in this group too, but no managed standalone hook reads it",
		}, []string{
			"variables (`DEFENSECLAW_FAIL_MODE`, `DEFENSECLAW_STRICT_AVAILABILITY`, `DEFENSECLAW_HOOK_MAX_BODY`) are honored only when they make the setting stricter",
		}},
		{filepath.Join(docs, "enterprise", "threat-model.mdx"), []string{
			"reads no fail mode from the environment: it follows the administrator's installed `hook_fail_mode`",
			"and no managed standalone hook reads `DEFENSECLAW_FAIL_MODE`",
		}, []string{
			"always fails closed, never open",
			"Three variables (`DEFENSECLAW_FAIL_MODE`",
		}},
		{filepath.Join(docs, "reference", "source-of-truth.mdx"), []string{
			"`DEFENSECLAW_FAIL_MODE`, which no managed standalone hook reads",
		}, []string{
			"| `DEFENSECLAW_FAIL_MODE`, `DEFENSECLAW_STRICT_AVAILABILITY`, `DEFENSECLAW_HOOK_MAX_BODY` |",
		}},
	} {
		data, err := os.ReadFile(doc.path)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		for _, want := range doc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s: missing %q", doc.path, want)
			}
		}
		for _, forbidden := range doc.forbidden {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s still promises an environment fail-mode override: %q", doc.path, forbidden)
			}
		}
	}
}

// 1.0.4 review (loop round 2 after round 4 of G-hooks-upg): pages said no
// hook reads DEFENSECLAW_FAIL_MODE, while the Antigravity, Devin, Hermes and
// Kiro shell hooks of a Secure Client deployment take it as a full override
// (FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-...}" in their SecureClientDelivery
// branch). Every docs paragraph or table row that says the variable is not
// read names that exception, and so does the registry sentence the env-var
// reference shows.
func TestFailModeEnvDocsNameTheSecureClientException(t *testing.T) {
	repo := filepath.Join("..", "..", "..", "..")
	for _, script := range []string{"antigravity-hook.sh", "devin-hook.sh", "hermes-hook.sh", "kiro-hook.sh"} {
		data, err := os.ReadFile(filepath.Join(repo, "internal", "gateway", "connector", "hooks", script))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `{{else if .SecureClientDelivery}}FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-`) {
			t.Fatalf("%s: the Secure Client render no longer reads DEFENSECLAW_FAIL_MODE; update the docs and this test", script)
		}
	}
	claim := regexp.MustCompile("(?i)\\bno (?:[a-z]+ ){0,3}hooks? reads?\\b|\\bnot read by [^|]{0,40}?hooks\\b|`DEFENSECLAW_FAIL_MODE` is not read")
	unqualified := regexp.MustCompile(`(?i)\bno hooks? reads?\b`)
	units := func(text string) []string {
		var out []string
		var paragraph []string
		flush := func() {
			if len(paragraph) > 0 {
				out = append(out, strings.Join(paragraph, " "))
				paragraph = nil
			}
		}
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			switch {
			case trimmed == "":
				flush()
			case strings.HasPrefix(trimmed, "|"):
				flush()
				out = append(out, trimmed)
			default:
				paragraph = append(paragraph, trimmed)
			}
		}
		flush()
		return out
	}
	checked := 0
	err := filepath.WalkDir(filepath.Join(repo, "docs-site", "content"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".mdx") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, unit := range units(string(data)) {
			unit = strings.Join(strings.Fields(unit), " ")
			if !strings.Contains(unit, "DEFENSECLAW_FAIL_MODE") || !claim.MatchString(unit) {
				continue
			}
			checked++
			if !strings.Contains(unit, "Secure Client") {
				t.Errorf("%s: says DEFENSECLAW_FAIL_MODE is not read without the Secure Client exception: %.200q", path, unit)
			}
			if unqualified.MatchString(unit) {
				t.Errorf("%s: says no hook reads it at all: %.200q", path, unit)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Source of truth, enterprise overview, threat model, troubleshooting,
	// the env-var reference, and two in the fail-mode reference.
	if checked < 7 {
		t.Fatalf("checked %d docs statements, want the seven that make one", checked)
	}
	data, err := os.ReadFile(filepath.Join(repo, "internal", "envvars", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Entries []struct {
			Name    string `json:"name"`
			Purpose string `json:"purpose"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, variable := range registry.Entries {
		if variable.Name != "DEFENSECLAW_FAIL_MODE" {
			continue
		}
		found = true
		// The env-var reference shows the first sentence only.
		first, _, _ := strings.Cut(variable.Purpose, ". ")
		if !strings.Contains(first, "Secure Client") {
			t.Errorf("registry purpose first sentence leaves out the Secure Client exception: %q", first)
		}
	}
	if !found {
		t.Fatal("DEFENSECLAW_FAIL_MODE is not in the registry")
	}
}

// GAP-0346: only an outage of a standalone hook in fail mode open lets the
// call through when the foreign-hook guard cannot reach the gateway.
func TestManagedOutageFailsOpenOnlyForAnOpenStandaloneOutage(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", errManagedGatewayNotRunning)
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
		err    error
		want   bool
	}{
		{name: "unset", mutate: func(o *Options) { o.FailMode = "" }, err: notRunning},
		{name: "closed", mutate: func(o *Options) { o.FailMode = "closed" }, err: notRunning},
		{name: "open, not running", err: notRunning, want: true},
		{name: "open, restarting", err: fmt.Errorf("session exchange: %w", errGatewayRestarting), want: true},
		{name: "open, no answer", err: fmt.Errorf("session exchange: %w", errGatewayNoAnswer), want: true},
		{name: "open, port held", err: fmt.Errorf("%w: %w", errManagedGatewayPortHeld, errManagedGatewayNotRunning)},
		{name: "open, unverified peer", err: errManagedGatewayPeerUnverified},
		{name: "open, unusable answer", err: errors.New("invalid session gateway decision")},
		{name: "open, no error"},
		{name: "open, strict availability", mutate: func(o *Options) { o.StrictAvailability = true }, err: notRunning},
		{name: "open, runtime failure", mutate: func(o *Options) { o.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid" }, err: notRunning},
		{name: "open, Secure Client", mutate: func(o *Options) { o.SecureClient = true }, err: notRunning},
		{name: "open, per-user", mutate: func(o *Options) { o.ManagedEnterprise = false }, err: notRunning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{Connector: "copilot", ManagedEnterprise: true, ExplainUnenrolledAccount: true, FailMode: "open"}
			if tc.mutate != nil {
				tc.mutate(&opts)
			}
			if got := ManagedOutageFailsOpen(opts, tc.err); got != tc.want {
				t.Fatalf("ManagedOutageFailsOpen = %v, want %v", got, tc.want)
			}
		})
	}
}

// Re-review P1: a standalone hook in fail mode open that gets a 401 or 403
// status line followed by a body it cannot read (cut off, or over the cap)
// blocks: the status already says the credential was refused, an integrity
// failure, closed in every fail mode.
func TestStandaloneManagedAuthRefusalWithAnUnreadableBodyStaysClosed(t *testing.T) {
	original := hookAuthRetryDelay
	hookAuthRetryDelay = time.Millisecond
	t.Cleanup(func() { hookAuthRetryDelay = original })
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		for name, body := range map[string]func() io.ReadCloser{
			"truncated": func() io.ReadCloser { return io.NopCloser(&failingReader{data: []byte(`{"error":"unauth`)}) },
			"oversized": func() io.ReadCloser {
				return io.NopCloser(strings.NewReader(`{"error":"` + strings.Repeat("x", int(defaultMaxBody)+16) + `"}`))
			},
		} {
			rt := &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: body(), Header: make(http.Header)}, nil
			}}
			result := run(t, "codex", rt, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.FailMode = "open"
			})
			if !blocked(result) {
				t.Fatalf("HTTP %d with a %s body allowed an open standalone call: code=%d stdout=%q stderr=%q", status, name, result.code, result.stdout, result.stderr)
			}
		}
	}
}

// failingReader returns data, then a read error: a body the gateway cut off.
type failingReader struct {
	data []byte
	done bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.ErrUnexpectedEOF
	}
	r.done = true
	return copy(p, r.data), nil
}

// Re-review P2: a managed standalone Copilot hook whose command binds no
// reviewed Copilot event never answers allow: in every fail mode it writes
// Copilot's two native denies (preToolUse and permissionRequest, the only
// Copilot events that can block). A per-user hook keeps Copilot's documented
// fail-open result.
func TestInvalidManagedCopilotEventBindingNeverAllows(t *testing.T) {
	for _, event := range []string{"", "bogusEvent", "PreToolUse"} {
		for _, mode := range []string{"", "open", "closed"} {
			rt := ok(`{"action":"allow"}`)
			result := run(t, "copilot", rt, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.Event = event
				o.FailMode = mode
			})
			if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) || !strings.Contains(result.stdout, `"behavior":"deny"`) {
				t.Fatalf("event %q, fail mode %q: stdout=%q stderr=%q code=%d", event, mode, result.stdout, result.stderr, result.code)
			}
			if !strings.Contains(result.stderr, invalidManagedCopilotBindingReason) || rt.requests != 0 {
				t.Fatalf("event %q: the refusal must name its reason and never reach the gateway: stderr=%q requests=%d", event, result.stderr, rt.requests)
			}
		}
	}
	perUser := run(t, "copilot", ok(`{"action":"allow"}`), func(o *Options) { o.Event = "bogusEvent"; o.FailMode = "closed" })
	if strings.Contains(perUser.stdout, "deny") {
		t.Fatalf("a per-user hook keeps Copilot's fail-open result: stdout=%q", perUser.stdout)
	}
}

// GAP-0349 (OpenCode) and GAP-0350 (Copilot) on managed Windows, GAP-0346
// on macOS: the managed OpenCode and Copilot tool-call hooks follow the
// administrator's fail mode when the gateway service is not running, on
// every OS: unset and closed block, open allows.
func TestStandaloneManagedOpenCodeAndCopilotFollowTheAdministratorsFailMode(t *testing.T) {
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for connector, event := range map[string]string{"opencode": "tool.execute.before", "copilot": "preToolUse"} {
		for mode, wantBlock := range map[string]bool{"": true, "open": false, "closed": true} {
			result := run(t, connector, &stubRT{err: notRunning}, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.Event = event
				o.FailMode = mode
				o.Stdin = strings.NewReader(`{"tool":"bash","args":{"command":"echo ok"},"toolName":"bash","toolArgs":"{}"}`)
			})
			if got := blocked(result); got != wantBlock {
				t.Fatalf("%s, fail mode %q: blocked = %v, want %v: code=%d stdout=%q stderr=%q",
					connector, mode, got, wantBlock, result.code, result.stdout, result.stderr)
			}
		}
	}
}

// Final review P2: a missing answer counts as the gateway's outage, which
// fail mode open lets through, only when the gateway contact had at least
// hookGatewayAnswerFloor of the answer budget. A slow local step (a
// foreign-hook scan close to its own budget) that leaves less fails closed,
// for the session exchange and for the hook request.
func TestStandaloneManagedNoAnswerAfterASlowLocalStepStaysClosed(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	previousFloor := hookGatewayAnswerFloor
	hookGatewayAnswerFloor = 200 * time.Millisecond
	t.Cleanup(func() { hookGatewayAnswerFloor = previousFloor })
	addr := hungGateway(t)

	for _, tc := range []struct {
		name  string
		spent time.Duration
		open  bool
	}{
		{name: "the gateway had the budget", spent: 0, open: true},
		{name: "a local step spent the budget", spent: 250 * time.Millisecond, open: false},
	} {
		t.Run("session exchange: "+tc.name, func(t *testing.T) {
			token := "authenticated-generation-token"
			opts := Options{ManagedEnterprise: true, AuthenticatedManagedToken: &token, APIAddr: addr,
				HTTPClient: &http.Client{}, Connector: "copilot", Event: "preToolUse", FailMode: "open",
				StartedAt: time.Now().Add(-tc.spent)}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := ExchangeForeignHookSession(ctx, opts, "copilot", []byte(`{}`))
			if !errors.Is(err, errGatewayNoAnswer) {
				t.Fatalf("err = %v, want a missing answer", err)
			}
			if got := errors.Is(err, errAnswerBudgetSpentLocally); got == tc.open {
				t.Fatalf("spent locally = %v, want %v (err %v)", got, !tc.open, err)
			}
			if got := ManagedOutageFailsOpen(opts, err); got != tc.open {
				t.Fatalf("ManagedOutageFailsOpen = %v, want %v (err %v)", got, tc.open, err)
			}
		})
		t.Run("hook request: "+tc.name, func(t *testing.T) {
			started := time.Now().Add(-tc.spent)
			result := run(t, "codex", nil, func(o *Options) {
				managedCodex(o)
				o.ExplainUnenrolledAccount = true
				o.FailMode = "open"
				o.APIAddr = addr
				o.HTTPClient = &http.Client{}
				o.StartedAt = started
			})
			if blocked(result) == tc.open {
				t.Fatalf("blocked = %v, want %v: code=%d stdout=%q stderr=%q", blocked(result), !tc.open, result.code, result.stdout, result.stderr)
			}
		})
	}
}

// GAP-0351: the managed OpenCode plugin reads an empty answer as closed, so a
// standalone OpenCode hook in fail mode open answers an outage with an
// explicit allow that carries the fail-open notice; closed keeps the deny.
func TestStandaloneManagedOpenCodeFailOpenAnswersAnExplicitAllow(t *testing.T) {
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for _, mode := range []string{"open", "closed"} {
		result := run(t, "opencode", &stubRT{err: notRunning}, func(o *Options) {
			managedCodex(o)
			o.ExplainUnenrolledAccount = true
			o.Event = "tool.execute.before"
			o.FailMode = mode
			o.Stdin = strings.NewReader(`{"tool":"bash","args":{"command":"echo ok"}}`)
		})
		var answer struct {
			HookOutput struct {
				Decision string `json:"decision"`
			} `json:"hook_output"`
			FailOpen bool   `json:"fail_open"`
			Notice   string `json:"notice"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result.stdout)), &answer); err != nil {
			t.Fatalf("fail mode %s: the answer is not one JSON object: %q (%v)", mode, result.stdout, err)
		}
		if mode == "closed" {
			if answer.HookOutput.Decision != "deny" || result.code == 0 {
				t.Fatalf("closed: want the deny, got code=%d stdout=%q", result.code, result.stdout)
			}
			continue
		}
		if result.code != 0 || answer.HookOutput.Decision != "allow" || !answer.FailOpen ||
			!strings.Contains(answer.Notice, "fail mode is open") || !strings.Contains(answer.Notice, managedGatewayNotRunningReason) {
			t.Fatalf("open: want an explicit allow with the notice, got code=%d stdout=%q", result.code, result.stdout)
		}
	}
}

// Bounded review P1: oversized tool input reaches handleOversized before the
// gateway is contacted. On a standalone host it is not an outage, so it is
// blocked in fail mode open for every connector, and the managed OpenCode
// plugin never gets its explicit allow for it. Per-user hooks keep their
// open result.
func TestStandaloneManagedOversizedInputBlocksUnderOpenForEveryConnector(t *testing.T) {
	events := map[string]string{
		"claudecode": "PreToolUse",
		"codex":      "PreToolUse",
		"copilot":    "preToolUse",
		"hermes":     "pre_tool_call",
		"opencode":   "tool.execute.before",
	}
	for connector, event := range events {
		result := run(t, connector, ok(`{"action":"allow"}`), func(o *Options) {
			managedCodex(o)
			o.ExplainUnenrolledAccount = true
			o.FailMode = "open"
			o.Event = event
			o.MaxBody = 8
			o.Stdin = strings.NewReader(`{"hook_event_name":"` + event + `","tool_input":{"command":"` + strings.Repeat("x", 64) + `"}}`)
		})
		if !blocked(result) {
			t.Fatalf("%s: oversized input under admin open was allowed: code=%d stdout=%q stderr=%q", connector, result.code, result.stdout, result.stderr)
		}
		if strings.Contains(result.stdout, `"fail_open":true`) || strings.Contains(result.stdout, `"decision":"allow"`) {
			t.Fatalf("%s: oversized input got an explicit allow: %q", connector, result.stdout)
		}
	}
	// A per-user hook in fail mode open keeps its open result.
	perUser := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
		o.MaxBody = 8
		o.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_input":{"command":"` + strings.Repeat("x", 64) + `"}}`)
	})
	if blocked(perUser) {
		t.Fatalf("per-user open: oversized input must keep the open result: code=%d stdout=%q", perUser.code, perUser.stdout)
	}
}

// Bounded review P1: the managed OpenCode explicit allow comes only from an
// outage (the gateway not running, restarting, or no answer). Every other
// failure on a standalone host under admin open blocks: oversized input, a
// transport error that is not an outage, an error status, an unusable answer.
func TestStandaloneManagedOpenCodeExplicitAllowOnlyOnAnOutage(t *testing.T) {
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	for _, tc := range []struct {
		name    string
		rt      *stubRT
		maxBody int64
		allowed bool
	}{
		{name: "gateway not running", rt: &stubRT{err: notRunning}, allowed: true},
		{name: "oversized input", rt: ok(`{"action":"allow"}`), maxBody: 8},
		{name: "transport error", rt: &stubRT{err: errors.New("offline")}},
		{name: "gateway 5xx", rt: &stubRT{status: 500, body: "boom"}},
		{name: "unusable answer", rt: ok("not-json")},
		{name: "port held", rt: &stubRT{err: fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayPortHeld)}},
	} {
		result := run(t, "opencode", tc.rt, func(o *Options) {
			managedCodex(o)
			o.ExplainUnenrolledAccount = true
			o.FailMode = "open"
			o.Event = "tool.execute.before"
			o.MaxBody = tc.maxBody
			o.Stdin = strings.NewReader(`{"tool":"bash","args":{"command":"echo ok"}}`)
		})
		explicit := strings.Contains(result.stdout, `"fail_open":true`)
		if explicit != tc.allowed || blocked(result) == tc.allowed {
			t.Fatalf("%s: explicit allow = %v, blocked = %v, want allowed %v: code=%d stdout=%q stderr=%q",
				tc.name, explicit, blocked(result), tc.allowed, result.code, result.stdout, result.stderr)
		}
	}
}
