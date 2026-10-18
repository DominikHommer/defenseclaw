// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func shortProgressCeiling(t *testing.T, ceiling time.Duration) {
	t.Helper()
	previous := hookProgressCeiling
	hookProgressCeiling = ceiling
	t.Cleanup(func() { hookProgressCeiling = previous })
}

const preToolUsePayload = `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`

// GAP-0155 (BM-03, BM-05): the work the hook command does before Run (the
// managed runtime descriptor, the account, the sidecar) counts against the
// call's budget. A call held there is answered, blocked, by its deadline by
// the watchdog the command armed first, and Run's own later result is
// discarded: one answer.
func TestEarlyAnswerWatchdogAnswersWhileTheWorkBeforeRunIsHeld(t *testing.T) {
	const budget = 300 * time.Millisecond
	shortAnswerBudget(t, budget)
	stdout := &firstWriteRecorder{}
	exited := make(chan int, 1)
	started := time.Now()
	watchdog := ArmAnswerWatchdog(Options{
		Connector:         "claudecode",
		ManagedEnterprise: true,
		FailMode:          "open",
		StartedAt:         started,
		Stdout:            stdout,
		Stderr:            &firstWriteRecorder{},
		Exit:              func(code int) { exited <- code },
	}, []byte(preToolUsePayload))
	if watchdog == nil {
		t.Fatal("no watchdog for a managed PreToolUse call")
	}
	var code int
	select {
	case code = <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("no answer while the work before Run was held")
	}
	out, first := stdout.read()
	if late := first.Sub(started); late > budget+500*time.Millisecond {
		t.Fatalf("the answer came %s after the call started, want by the %s budget", late, budget)
	}
	if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, managedGatewayNoAnswerReason) {
		t.Fatalf("exit %d stdout %q, want the managed deny naming %s (closed although the flag says open)", code, out, managedGatewayNoAnswerReason)
	}
	// The held work ends and Run answers allow: discarded.
	result := run(t, "claudecode", &stubRT{status: http.StatusOK, body: `{"action":"allow"}`}, func(opts *Options) {
		managedCodex(opts)
		opts.StartedAt = started
		opts.Stdin = strings.NewReader(preToolUsePayload)
		opts.AnswerWatchdog = watchdog
	})
	if result.code != 0 || result.stdout != "" {
		t.Fatalf("Run after the watchdog answered: code %d stdout %q, want nothing more", result.code, result.stdout)
	}
	if out, _ := stdout.read(); strings.Count(out, `"permissionDecision":"`) != 1 {
		t.Fatalf("stdout %q, want exactly one answer", out)
	}
}

// Run adopts the watchdog the command armed: the call answered in time
// gets the gateway's decision, once, and the watchdog never fires.
func TestEarlyAnswerWatchdogIsAdoptedByRun(t *testing.T) {
	shortAnswerBudget(t, 400*time.Millisecond)
	for _, body := range []string{`{"action":"allow"}`, `{"action":"block","reason":"policy rule"}`} {
		stdout := &firstWriteRecorder{}
		exited := make(chan int, 1)
		started := time.Now()
		watchdog := ArmAnswerWatchdog(Options{
			Connector: "claudecode", ManagedEnterprise: true, StartedAt: started,
			Stdout: stdout, Stderr: &firstWriteRecorder{}, Exit: func(code int) { exited <- code },
		}, []byte(preToolUsePayload))
		result := run(t, "claudecode", &stubRT{status: http.StatusOK, body: body}, func(opts *Options) {
			managedCodex(opts)
			opts.StartedAt = started
			opts.Stdin = strings.NewReader(preToolUsePayload)
			opts.AnswerWatchdog = watchdog
		})
		time.Sleep(600 * time.Millisecond)
		select {
		case code := <-exited:
			t.Fatalf("%s: the watchdog ended the process (%d) after the call was answered", body, code)
		default:
		}
		out, _ := stdout.read()
		if strings.Contains(out, managedGatewayNoAnswerReason) || result.stdout != "" {
			t.Fatalf("%s: watchdog stdout %q, test buffer %q: the answer must go through the watchdog's writer alone", body, out, result.stdout)
		}
		if denied := strings.Contains(out, `"permissionDecision":"deny"`); denied != strings.Contains(body, "block") {
			t.Fatalf("%s: stdout %q does not carry the gateway's decision", body, out)
		}
	}
}

// Only a tool call outside Secure Client gets the early watchdog; an event
// that turns out not to be a tool call in Run stands it down.
func TestEarlyAnswerWatchdogOnlyForToolCalls(t *testing.T) {
	shortAnswerBudget(t, 200*time.Millisecond)
	base := Options{Connector: "claudecode", ManagedEnterprise: true, StartedAt: time.Now(), Exit: func(int) { t.Error("the watchdog ended the process") }}
	for name, test := range map[string]struct {
		opts    Options
		payload string
	}{
		"session start": {base, `{"hook_event_name":"SessionStart"}`},
		"prompt":        {base, `{"hook_event_name":"UserPromptSubmit"}`},
		"no event":      {base, `{}`},
		"no start time": {func() Options { o := base; o.StartedAt = time.Time{}; return o }(), preToolUsePayload},
		"secure client": {func() Options { o := base; o.SecureClient = true; return o }(), preToolUsePayload},
		"unknown agent": {func() Options { o := base; o.Connector = "nope"; return o }(), preToolUsePayload},
	} {
		if watchdog := ArmAnswerWatchdog(test.opts, []byte(test.payload)); watchdog != nil {
			t.Fatalf("%s: armed a watchdog", name)
		}
	}
	// Armed from the command line's --event, the payload names another
	// event: Run stands the watchdog down.
	stdout := &firstWriteRecorder{}
	opts := base
	opts.Event, opts.Stdout, opts.Stderr = "PreToolUse", stdout, &firstWriteRecorder{}
	watchdog := ArmAnswerWatchdog(opts, []byte(`{}`))
	if watchdog == nil {
		t.Fatal("no watchdog for --event PreToolUse")
	}
	run(t, "claudecode", &stubRT{status: http.StatusOK, body: `{"action":"allow"}`}, func(o *Options) {
		managedCodex(o)
		o.Event = "SessionStart"
		o.StartedAt = opts.StartedAt
		o.AnswerWatchdog = watchdog
		o.Stdin = strings.NewReader(`{"hook_event_name":"SessionStart"}`)
	})
	time.Sleep(400 * time.Millisecond)
	if out, _ := stdout.read(); strings.Contains(out, managedGatewayNoAnswerReason) {
		t.Fatalf("stdout %q: the watchdog answered a SessionStart", out)
	}
}

// GAP-0255: a 102 report that the gateway waits on a remote scanner moves
// the answer deadline to the progress ceiling, never further: a judge that
// answers later is not waited for, the managed call is blocked (whatever its
// fail mode) and the process ends at the ceiling.
func TestProgressReportWaitsNoLongerThanTheCeiling(t *testing.T) {
	const budget, ceiling = 200 * time.Millisecond, 700 * time.Millisecond
	shortAnswerBudget(t, budget)
	shortProgressCeiling(t, ceiling)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	addr := gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(HookProgressStatus)
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	})
	result, elapsed := runAgainstGateway(t, "codex", addr, func(opts *Options) {
		managedCodex(opts)
		opts.FailMode = "open"
	})
	if elapsed < ceiling-100*time.Millisecond || elapsed > ceiling+500*time.Millisecond {
		t.Fatalf("the call ended after %s, want at the %s ceiling (not the %s budget, not the judge)", elapsed, ceiling, budget)
	}
	if !blocked(result) || !strings.Contains(result.stdout+result.stderr, managedGatewayNoAnswerReason) {
		t.Fatalf("code=%d stdout=%q stderr=%q, want the managed no-answer block", result.code, result.stdout, result.stderr)
	}

	// The watchdog follows the ceiling too: the process ends there.
	stdout := &firstWriteRecorder{}
	exited := make(chan int, 1)
	started := time.Now()
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		run(t, "claudecode", nil, func(opts *Options) {
			managedCodex(opts)
			opts.APIAddr = addr
			opts.HTTPClient = &http.Client{}
			opts.StartedAt = started
			opts.Stdout = stdout
			opts.Exit = func(code int) { exited <- code }
		})
	}()
	t.Cleanup(func() { <-returned })
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the watchdog did not end the call at the ceiling")
	}
	out, first := stdout.read()
	if late := first.Sub(started); late < ceiling-100*time.Millisecond || late > ceiling+500*time.Millisecond {
		t.Fatalf("the watchdog answered %s after the start, want at the %s ceiling", late, ceiling)
	}
	if !strings.Contains(out, managedGatewayNoAnswerReason) {
		t.Fatalf("stdout %q, want the managed no-answer deny", out)
	}
}
