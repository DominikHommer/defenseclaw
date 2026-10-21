// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// newEndedVM is a MicroVM gateway running the sandbox name, with the
// manager on a fake clock (advance moves it on).
func newEndedVM(t *testing.T, name string) (e *harnessEnv, advance func(time.Duration)) {
	t.Helper()
	e = newVMEnv(t, nil)
	useOpenCode(t, e)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: name, Harness: "opencode", Copy: true})
	e.watch.waitStarted(t, name)
	_, advance = e.fakeClock(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	return e, advance
}

// endIn puts the sandbox name in phase, in OpenShell and as the manager
// saw it.
func endIn(t *testing.T, e *harnessEnv, name string, phase openshell.SandboxPhase, conds ...stream.Condition) {
	t.Helper()
	must(t, e.fake.SetPhase(openshell.DefaultWorkspace, name, phase))
	e.m.statusEvent(t.Context(), e.boxOf(name), &stream.Status{Phase: phase, Conditions: conds})
}

// busy is what the status says a stop of the gateway waits for.
func busy(t *testing.T, e *harnessEnv) int {
	t.Helper()
	st, err := e.m.Status(t.Context())
	if err != nil || st.Live == nil {
		t.Fatalf("status = %+v, %v", st, err)
	}
	return st.Busy()
}

// syncsIn counts the sync(1) commands tried in the sandbox name since the
// first n exec calls: OpenShell refuses a command in a sandbox that is not
// ready (the fake too), so DefenseClaw must not count on one there.
func syncsIn(e *harnessEnv, name string, n int) int {
	got := 0
	for _, c := range e.fake.ExecCalls()[n:] {
		if c.Sandbox == name && len(c.Command) == 1 && c.Command[0] == "/bin/sync" {
			got++
		}
	}
	return got
}

var (
	mainFailed  = stream.Condition{Type: "Ready", Status: "False", Reason: "MainProcessFailed", Message: "Canonical main process exited with status 1"}
	vmExited    = stream.Condition{Type: "Ready", Status: "False", Reason: "ProcessExited", Message: "VM process exited with status 1"}
	vmUnpolled  = stream.Condition{Type: "Ready", Status: "False", Reason: "ProcessPollFailed", Message: "Bad file descriptor"}
	provTimeout = stream.Condition{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"}
)

// A MicroVM whose workload ended still runs its VM (GAP-0012), and nothing
// in OpenShell flushes it: it runs no command in it, and its stop returns
// it as it is. The round before counted on a sync(1) exec that OpenShell
// refuses. Its guest writes its disk back on its own, so the status counts
// it (a managed switch, the daemon's idle stop of the gateway and an
// upgrade wait for it) for openshell.EndedSettle from when DefenseClaw saw
// its workload end, or saw its harness at work after that, or loaded it.
// One whose VM OpenShell could not poll may still run, and counts until
// it leaves that state; one whose provisioning timed out ran nothing. On
// docker a completed sandbox is an exited container: nothing waits.
func TestAnEndedMicroVMCountsUntilItsDiskIsWrittenBack(t *testing.T) {
	e, advance := newEndedVM(t, "donebox")
	n := len(e.fake.ExecCalls())
	endIn(t, e, "donebox", openshell.PhaseCompleted)
	if got := busy(t, e); got != 1 {
		t.Fatalf("a completed MicroVM: busy %d, want 1", got)
	}
	advance(openshell.EndedSettle - time.Second)
	if got := busy(t, e); got != 1 {
		t.Fatalf("a completed MicroVM before its disk is written back: busy %d", got)
	}
	advance(time.Second)
	if got := busy(t, e); got != 0 {
		t.Fatalf("a completed MicroVM %s after its end: busy %d", openshell.EndedSettle, got)
	}
	list, err := e.m.List(t.Context())
	must(t, err)
	for _, v := range list {
		if v.Name == "donebox" && (v.EndedAt.IsZero() || HoldsCompute(v, e.m.now()) || !HoldsCompute(v, v.EndedAt.Add(time.Minute))) {
			t.Fatalf("the view: ended at %v, holds compute now %v", v.EndedAt, HoldsCompute(v, e.m.now()))
		}
	}

	// Its harness at work after the end (a process that outlived the main
	// one) starts the wait over.
	b := e.boxOf("donebox")
	e.m.mu.Lock()
	b.noteActiveLocked(e.m.now())
	e.m.mu.Unlock()
	if got := busy(t, e); got != 1 {
		t.Fatalf("a completed MicroVM at work again: busy %d", got)
	}
	advance(openshell.EndedSettle)

	// Its stop: OpenShell returns it as it is, and nothing is run in it.
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.stopBox("donebox")
	if e.fake.Calls(openshelltest.MethodStopSandbox) != stops+1 || e.boxOf("donebox").phase != audit.SandboxPhaseCompleted {
		t.Fatalf("the stop of a completed MicroVM: phase %s", e.boxOf("donebox").phase)
	}
	if got := busy(t, e); got != 0 {
		t.Fatalf("the stop of a completed MicroVM started its wait over: busy %d", got)
	}
	if got := syncsIn(e, "donebox", n); got != 0 {
		t.Fatalf("%d sync(1) tried in a completed MicroVM", got)
	}

	// A daemon that loads it again cannot tell what happened meanwhile.
	e.m.mu.Lock()
	b.phase = ""
	e.m.mu.Unlock()
	endIn(t, e, "donebox", openshell.PhaseCompleted)
	if got := busy(t, e); got != 1 {
		t.Fatalf("a completed MicroVM a daemon loads: busy %d", got)
	}

	for _, tc := range []struct {
		cond stream.Condition
		busy int
	}{{mainFailed, 1}, {vmExited, 1}, {provTimeout, 0}, {vmUnpolled, 1}} {
		endIn(t, e, "donebox", openshell.PhaseProvisioning)
		endIn(t, e, "donebox", openshell.PhaseError, tc.cond)
		if got := busy(t, e); got != tc.busy {
			t.Errorf("a MicroVM in the error state (%s): busy %d, want %d", tc.cond.Reason, got, tc.busy)
		}
		advance(openshell.EndedSettle)
		want := 0
		if tc.cond.Reason == "ProcessPollFailed" {
			want = 1
		}
		if got := busy(t, e); got != want {
			t.Errorf("a MicroVM in the error state (%s), %s on: busy %d, want %d", tc.cond.Reason, openshell.EndedSettle, got, want)
		}
	}
	// A daemon restart's reconcile republishes the error state without its
	// conditions: the reason stays.
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseError, audit.SandboxTriggerReconcile, true, nil, nil)
	if got := busy(t, e); got != 1 || !strings.Contains(e.boxOf("donebox").rec.PhaseReason, "ProcessPollFailed") {
		t.Fatalf("a republished error state: busy %d, reason %q", got, e.boxOf("donebox").rec.PhaseReason)
	}

	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dockerdone"})
	endIn(t, d, "dockerdone", openshell.PhaseCompleted)
	if got := busy(t, d); got != 0 {
		t.Fatalf("a completed docker sandbox: busy %d", got)
	}
	m := len(d.fake.ExecCalls())
	d.stopBox("dockerdone")
	if got := syncsIn(d, "dockerdone", m); got != 0 {
		t.Fatalf("a completed docker sandbox: %d sync(1) tried", got)
	}
}

// An OpenShell before 0.1.5 (the 0.1.3 of DefenseClaw 1.0.3) neither stops
// nor starts a MicroVM in its error state, and DefenseClaw starts no
// sandbox on it. The round before had its stop flush the MicroVM first,
// with an exec that OpenShell refuses in that state, and its advice said
// so. Nothing flushes it; its guest writes its disk back on its own, so the
// upgrade (per user, or the managed pin move) waits openshell.EndedSettle
// for it and then keeps its work, which the feed, the refused stop and the
// status say. One whose VM OpenShell could not poll may still run: the
// upgrade waits for it until it leaves that state or is deleted.
func TestOldGatewayErrorMicroVMWaitsForItsDiskThenTheUpgrade(t *testing.T) {
	e, advance := newEndedVM(t, "box")
	connectAtFakeRelease(e)
	e.fake.SetRelease("0.1.3")
	if _, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Harness: "opencode", Copy: true, Project: e.otherProject("other")}); err == nil {
		t.Fatal("a create on 0.1.3 succeeded")
	}
	if got := e.m.gatewayRelease(); got != "0.1.3" {
		t.Fatalf("gateway release = %q", got)
	}
	upgrade := "upgrade OpenShell 0.1.3 to " + openshell.InstallerVersion + " in place with `defenseclaw sandbox setup --install-openshell`"
	n := len(e.fake.ExecCalls())
	feedLine := func() string {
		var line string
		for _, ev := range e.events("box", sandboxapi.ActivityLifecycle, "") {
			if ev.Phase == string(audit.SandboxPhaseError) {
				line = ev.Message
			}
		}
		return line
	}
	endIn(t, e, "box", openshell.PhaseError, vmExited)
	wayOn := "nothing flushes its MicroVM, whose guest writes its disk back on its own within " + openshell.EndedSettleWords() +
		" of its workload's end: the upgrade waits for that, and so keeps its work. " + upgrade + ", then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`"
	if line := feedLine(); !strings.Contains(line, wayOn) || strings.Contains(line, "flushes the MicroVM's disk all the same") {
		t.Fatalf("the feed's line: %q", line)
	}
	if got := busy(t, e); got != 1 {
		t.Fatalf("a MicroVM in the error state: busy %d", got)
	}

	refused := &types.StatusError{Code: types.ErrorConflict, Message: "sandbox must be Ready or in an automatic restart to stop (current phase: Error)"}
	e.fake.FailNext(openshelltest.MethodStopSandbox, refused)
	_, err := e.m.Stop(t.Context(), "box")
	apiErr := wantCode(t, err, sandboxapi.CodeConflict)
	if !strings.Contains(apiErr.Message, "box is in OpenShell's error state") || !strings.Contains(apiErr.Detail, wayOn) ||
		strings.Contains(apiErr.Message+apiErr.Detail, "flushed its MicroVM's disk") {
		t.Fatalf("the refused stop = %+v", apiErr)
	}
	if got := syncsIn(e, "box", n); got != 0 {
		t.Fatalf("%d sync(1) tried in a MicroVM in the error state, which OpenShell refuses", got)
	}
	if got := busy(t, e); got != 1 {
		t.Fatalf("a refused stop: busy %d", got)
	}
	advance(openshell.EndedSettle)
	if got := busy(t, e); got != 0 {
		t.Fatalf("a MicroVM in the error state %s on: busy %d, want the upgrade to go ahead", openshell.EndedSettle, got)
	}

	// Its VM was not polled: it may still run.
	endIn(t, e, "box", openshell.PhaseProvisioning)
	endIn(t, e, "box", openshell.PhaseError, vmUnpolled)
	if line := feedLine(); !strings.Contains(line, "OpenShell could not tell whether its MicroVM still runs its workload, so the upgrade waits for it: "+
		"`defenseclaw sandbox delete box` ends that wait if its work is not needed; otherwise, once it has left that state, "+upgrade) {
		t.Fatalf("the feed's line for an unpolled MicroVM: %q", line)
	}
	advance(openshell.EndedSettle)
	if got := busy(t, e); got != 1 {
		t.Fatalf("an unpolled MicroVM: busy %d", got)
	}
}
