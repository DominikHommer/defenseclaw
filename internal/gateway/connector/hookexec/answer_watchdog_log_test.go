// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shortAnswerFloor lets a short test budget leave the gateway its answer
// window, so a missing answer is the gateway's outage (gatewayAnswerWindowShort).
func shortAnswerFloor(t *testing.T) {
	t.Helper()
	previous := hookGatewayAnswerFloor
	hookGatewayAnswerFloor = 50 * time.Millisecond
	t.Cleanup(func() { hookGatewayAnswerFloor = previous })
}

// standaloneOpenCodex is a managed Windows standalone Codex hook whose
// administrator chose fail mode open (outages only).
func standaloneOpenCodex(opts *Options) {
	managedWindowsStandalone(opts)
	opts.FailMode = "open"
}

// G-small loop 2, finding 1: a managed hook whose administrator chose fail
// mode open still refuses a failure that is not an outage. When the account
// lookup of its failure row stalls before the refusal is out, the watchdog
// answers at the deadline, and that answer is the call's closed one, not the
// fail-open answer of a gateway that gave none.
func TestWatchdogKeepsAKnownRefusalClosedWhileItsRowWaits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rt     *stubRT
		mutate func(*Options)
	}{
		{name: "unverified gateway peer", rt: &stubRT{err: errManagedGatewayPeerUnverified}},
		{name: "standalone hook without its socket", rt: ok(`{"action":"allow"}`),
			mutate: func(o *Options) { o.ManagedStandalone = true }},
		{name: "unverified peer, strict availability", rt: &stubRT{err: errManagedGatewayPeerUnverified},
			mutate: func(o *Options) { o.StrictAvailability = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortAnswerBudget(t, 400*time.Millisecond)
			shortAnswerFloor(t)
			logHome := t.TempDir()
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			stdout := &firstWriteRecorder{}
			exited := make(chan int, 1)
			returned := make(chan runResult, 1)
			go func() {
				returned <- run(t, "codex", tc.rt, func(o *Options) {
					standaloneOpenCodex(o)
					o.StartedAt = time.Now()
					o.Stdout = stdout
					o.Exit = func(code int) { exited <- code }
					o.FailureLogHome = func() string {
						<-release
						return logHome
					}
					if tc.mutate != nil {
						tc.mutate(o)
					}
				})
			}()
			select {
			case code := <-exited:
				out, _ := stdout.read()
				if !blocked(runResult{code: code, stdout: out}) {
					t.Fatalf("the watchdog answered exit %d stdout %q while the refusal's row waited, want the closed answer", code, out)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the watchdog did not answer while the refusal's row waited on the account lookup")
			}
			unblock()
			select {
			case result := <-returned:
				out, _ := stdout.read()
				if !blocked(runResult{code: result.code, stdout: out}) {
					t.Fatalf("Run returned %d stdout %q, want the closed answer", result.code, out)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return once the lookup ended")
			}
		})
	}
	// The outage itself still follows the administrator's open: the call
	// whose gateway does not answer is let through at the deadline.
	shortAnswerBudget(t, 400*time.Millisecond)
	shortAnswerFloor(t)
	hung := make(chan struct{})
	stdout := &firstWriteRecorder{}
	exited := make(chan int, 1)
	logHome := t.TempDir()
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		run(t, "codex", nil, func(o *Options) {
			standaloneOpenCodex(o)
			o.StartedAt = time.Now()
			o.HTTPClient = &http.Client{Transport: ignoringContextRT{release: hung}}
			o.Stdout = stdout
			o.Exit = func(code int) { exited <- code }
			o.FailureLogHome = userLogHome(logHome)
		})
	}()
	// Run ends before the budget is restored.
	t.Cleanup(func() { close(hung); <-returned })
	select {
	case code := <-exited:
		if out, _ := stdout.read(); blocked(runResult{code: code, stdout: out}) {
			t.Fatalf("no answer in fail mode open: exit %d stdout %q, want the administrator's open", code, out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the watchdog did not answer a gateway that gave no answer")
	}
}

// G-small loop 2, finding 2: the account lookup of a managed row can take
// longer than the watchdog's log wait (an NSS or a Windows profile lookup).
// The watchdog that answers a call still leaves its hook-failures row before
// the process ends, with one lookup for the call, both when Run starts the
// watchdog and when the hook command armed it before Run.
func TestWatchdogRowSurvivesASlowAccountLookup(t *testing.T) {
	const lookup = 250 * time.Millisecond
	if lookup <= answerWatchdogLogWait {
		t.Fatalf("the lookup (%s) must outlast the watchdog's log wait (%s)", lookup, answerWatchdogLogWait)
	}
	for _, tc := range []struct {
		name     string
		failMode string
		prearm   bool
	}{
		{"watchdog started by Run, fail mode closed", "closed", false},
		{"watchdog started by Run, fail mode open", "open", false},
		{"watchdog armed before Run, fail mode closed", "closed", true},
		{"watchdog armed before Run, fail mode open", "open", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortAnswerBudget(t, 800*time.Millisecond)
			shortAnswerFloor(t)
			logHome := t.TempDir()
			var lookups atomic.Int32
			resolve := func() string {
				lookups.Add(1)
				time.Sleep(lookup)
				return logHome
			}
			hung := make(chan struct{})
			rowAtExit := make(chan string, 1)
			exit := func(int) {
				row, _ := os.ReadFile(filepath.Join(logHome, "logs", "hook-failures.jsonl"))
				rowAtExit <- string(row)
			}
			started := time.Now()
			returned := make(chan struct{})
			// Run ends before the budget is restored.
			t.Cleanup(func() { close(hung); <-returned })
			go func() {
				defer close(returned)
				run(t, "codex", nil, func(o *Options) {
					managedWindowsStandalone(o)
					o.FailMode = tc.failMode
					o.StartedAt = started
					o.HTTPClient = &http.Client{Transport: ignoringContextRT{release: hung}}
					o.FailureLogHome = resolve
					if !tc.prearm {
						o.Exit = exit
						return
					}
					watchdog := ArmAnswerWatchdog(Options{
						Connector: "codex", Event: "PreToolUse", ManagedEnterprise: true,
						StartedAt: started, Exit: exit, Stdout: &strings.Builder{}, Stderr: &strings.Builder{},
					}, []byte(`{"hook_event_name":"PreToolUse"}`))
					if watchdog == nil {
						t.Error("the managed tool call armed no watchdog")
						return
					}
					watchdog.PrefetchFailureLogHome(resolve)
					o.AnswerWatchdog = watchdog
				})
			}()
			select {
			case row := <-rowAtExit:
				if strings.Count(row, "\n") != 1 || !strings.Contains(row, managedGatewayNoAnswerReason) {
					t.Fatalf("hook-failures.jsonl when the process ended = %q, want one %s row", row, managedGatewayNoAnswerReason)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the watchdog did not answer")
			}
			if n := lookups.Load(); n != 1 {
				t.Fatalf("the call looked the account up %d times, want once", n)
			}
		})
	}
}
