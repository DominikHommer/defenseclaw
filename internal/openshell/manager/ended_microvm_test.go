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
	"context"
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

// exitedWith gives the sandbox name in OpenShell the exit code of a main
// process that failed, whose stop OpenShell returns as it is.
func exitedWith(t *testing.T, e *harnessEnv, name string, code int32) {
	t.Helper()
	sb, err := e.fake.Sandboxes().Get(t.Context(), openshell.DefaultWorkspace, name)
	must(t, err)
	sb.Status.ExitCode = &code
	sb.ResourceVersion++
	e.fake.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
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

// letGoStop is the user's own stop (`defenseclaw sandbox stop`).
func letGoStop(t *testing.T, e *harnessEnv, name string) (*sandboxapi.Sandbox, error) {
	t.Helper()
	return e.m.Stop(sandboxapi.WithLetGo(t.Context()), name)
}

var (
	mainFailed  = stream.Condition{Type: "Ready", Status: "False", Reason: "MainProcessFailed", Message: "Canonical main process exited with status 1"}
	vmExited    = stream.Condition{Type: "Ready", Status: "False", Reason: "ProcessExited", Message: "VM process exited with status 1"}
	vmUnpolled  = stream.Condition{Type: "Ready", Status: "False", Reason: "ProcessPollFailed", Message: "Bad file descriptor"}
	provTimeout = stream.Condition{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"}
)

// A MicroVM whose workload ended still runs its VM (GAP-0012), with
// whatever its workload left running (a background process its main one
// forked), and nothing in OpenShell flushes or stops it: it runs no
// command in it, and its stop returns it as it is. The round before let
// such a MicroVM go two minutes after DefenseClaw saw its workload end, so
// a managed pin switch, the daemon's idle stop or an upgrade could then
// kill that process with its last writes unflushed. Now the status counts
// it (they wait for it) however long it has been so, until its user's own
// stop lets it go for the phase it is in, or it is deleted: a stop that
// DefenseClaw, a session or a pull makes lets none go, and a phase change
// holds it again. One whose VM is gone, or whose provisioning timed out,
// runs nothing; one whose VM OpenShell could not poll, or in the error
// state for another reason, may linger. On docker a completed sandbox is
// an exited container: nothing waits.
func TestALingeringMicroVMHoldsTheGatewayUntilItsUserLetsItGo(t *testing.T) {
	e, advance := newEndedVM(t, "donebox")
	n := len(e.fake.ExecCalls())
	endIn(t, e, "donebox", openshell.PhaseCompleted)
	if got := busy(t, e); got != 1 {
		t.Fatalf("a completed MicroVM: busy %d, want 1", got)
	}
	advance(24 * time.Hour)
	if got := busy(t, e); got != 1 {
		t.Fatalf("a completed MicroVM a day on: busy %d, want 1", got)
	}

	// A stop that is not its user's own (a session's end, a pull's, the
	// daemon's) lets nothing go: OpenShell returns it as it is.
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.stopBox("donebox")
	b := e.boxOf("donebox")
	if e.fake.Calls(openshelltest.MethodStopSandbox) != stops+1 || b.phase != audit.SandboxPhaseCompleted || busy(t, e) != 1 || b.rec.StopAskedIn != "" {
		t.Fatalf("a stop not the user's own: phase %s, busy %d, let go in %q", b.phase, busy(t, e), b.rec.StopAskedIn)
	}
	lb, unlock, err := e.m.lockBox("donebox")
	must(t, err)
	err = e.m.stop(t.Context(), lb, false)
	unlock()
	if err != nil || busy(t, e) != 1 {
		t.Fatalf("DefenseClaw's own stop: %v, busy %d", err, busy(t, e))
	}

	// Its user's own stop lets it go, and runs nothing in it.
	v, err := letGoStop(t, e, "donebox")
	if err != nil || v.Phase != "completed" || v.StopAskedIn != "completed" || HoldsCompute(*v) {
		t.Fatalf("the user's stop of a completed MicroVM = %+v, %v", v, err)
	}
	if got := busy(t, e); got != 0 {
		t.Fatalf("a completed MicroVM its user let go: busy %d", got)
	}
	if got := syncsIn(e, "donebox", n); got != 0 {
		t.Fatalf("%d sync(1) tried in a completed MicroVM", got)
	}
	// A daemon that loads it again keeps that.
	e.m.mu.Lock()
	b.phase = ""
	e.m.mu.Unlock()
	endIn(t, e, "donebox", openshell.PhaseCompleted)
	if got := busy(t, e); got != 0 {
		t.Fatalf("a let-go MicroVM a daemon loads: busy %d", got)
	}
	// Started again, and in another phase: it holds the gateway again.
	endIn(t, e, "donebox", openshell.PhaseProvisioning)
	if b.rec.StopAskedIn != "" {
		t.Fatalf("a phase change kept the let-go: %q", b.rec.StopAskedIn)
	}
	endIn(t, e, "donebox", openshell.PhaseCompleted)
	if got := busy(t, e); got != 1 {
		t.Fatalf("a completed MicroVM after a new session: busy %d", got)
	}

	for _, tc := range []struct {
		cond stream.Condition
		busy int
	}{{mainFailed, 1}, {vmUnpolled, 1}, {vmExited, 0}, {provTimeout, 0}} {
		endIn(t, e, "donebox", openshell.PhaseProvisioning)
		endIn(t, e, "donebox", openshell.PhaseError, tc.cond)
		advance(24 * time.Hour)
		if got := busy(t, e); got != tc.busy {
			t.Errorf("a MicroVM in the error state (%s) a day on: busy %d, want %d", tc.cond.Reason, got, tc.busy)
		}
	}
	// A daemon restart's reconcile republishes the error state without its
	// conditions: the reason stays.
	endIn(t, e, "donebox", openshell.PhaseProvisioning)
	endIn(t, e, "donebox", openshell.PhaseError, vmExited)
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseError, audit.SandboxTriggerReconcile, true, nil, nil)
	if got := busy(t, e); got != 0 || !strings.Contains(e.boxOf("donebox").rec.PhaseReason, "ProcessExited") {
		t.Fatalf("a republished error state: busy %d, reason %q", got, e.boxOf("donebox").rec.PhaseReason)
	}

	// Its main process failed: OpenShell returns its stop as it is, and
	// the user's own stop lets it go.
	endIn(t, e, "donebox", openshell.PhaseProvisioning)
	endIn(t, e, "donebox", openshell.PhaseError, mainFailed)
	exitedWith(t, e, "donebox", 1)
	if v, err := letGoStop(t, e, "donebox"); err != nil || v.StopAskedIn != "error" || busy(t, e) != 0 {
		t.Fatalf("the user's stop of a failed main process = %+v, %v (busy %d)", v, err, busy(t, e))
	}

	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dockerdone"})
	endIn(t, d, "dockerdone", openshell.PhaseCompleted)
	if got := busy(t, d); got != 0 {
		t.Fatalf("a completed docker sandbox: busy %d", got)
	}
	m := len(d.fake.ExecCalls())
	if v, err := letGoStop(t, d, "dockerdone"); err != nil || v.StopAskedIn != "" {
		t.Fatalf("the user's stop of a completed docker sandbox = %+v, %v", v, err)
	}
	if got := syncsIn(d, "dockerdone", m); got != 0 {
		t.Fatalf("a completed docker sandbox: %d sync(1) tried", got)
	}
}

// An OpenShell before 0.1.5 (the 0.1.3 of DefenseClaw 1.0.3) neither stops
// nor starts a MicroVM in its error state, and DefenseClaw starts no
// sandbox on it. The round before told the user the upgrade waits two
// minutes for its guest to write its disk back and then keeps its work.
// What its workload left running may still write: the upgrade (per user,
// or the managed pin move) now waits for it until its user lets it go,
// which the refused stop does when it is the user's own, or deletes it, as
// the feed and the refused stop say. One whose VM is gone runs nothing,
// and the way on is the upgrade, then stop and start.
func TestOldGatewayErrorMicroVMHoldsTheUpgradeUntilItsUserLetsItGo(t *testing.T) {
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
	for _, cond := range []stream.Condition{mainFailed, vmUnpolled} {
		endIn(t, e, "box", openshell.PhaseProvisioning)
		endIn(t, e, "box", openshell.PhaseError, cond)
		wayOn := "its MicroVM may still run what its workload left running, which nothing in OpenShell flushes or stops, so the upgrade waits for it: " +
			"`defenseclaw sandbox stop box` lets the upgrade stop it with the gateway (what is not on its disk by then is lost), and `defenseclaw sandbox delete box` deletes it. " +
			upgrade + ", then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`, which bring it back with its disk"
		if line := feedLine(); !strings.Contains(line, wayOn) || strings.Contains(line, "disk back") {
			t.Fatalf("the feed's line (%s): %q", cond.Reason, line)
		}
		advance(24 * time.Hour)
		if got := busy(t, e); got != 1 {
			t.Fatalf("a MicroVM in the error state (%s) a day on: busy %d", cond.Reason, got)
		}
	}

	refused := &types.StatusError{Code: types.ErrorConflict, Message: "sandbox must be Ready or in an automatic restart to stop (current phase: Error)"}
	// A stop that is not the user's own is refused and lets nothing go.
	e.fake.FailNext(openshelltest.MethodStopSandbox, refused)
	if _, err := e.m.Stop(t.Context(), "box"); err == nil || busy(t, e) != 1 {
		t.Fatalf("a refused stop not the user's own: %v, busy %d", err, busy(t, e))
	}
	e.fake.FailNext(openshelltest.MethodStopSandbox, refused)
	_, err := letGoStop(t, e, "box")
	apiErr := wantCode(t, err, sandboxapi.CodeConflict)
	if !strings.Contains(apiErr.Message, "box is in OpenShell's error state") || !strings.Contains(apiErr.Detail, LetGoNote("box")) ||
		!strings.Contains(apiErr.Detail, upgrade+", then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`") {
		t.Fatalf("the user's refused stop = %+v", apiErr)
	}
	if got := syncsIn(e, "box", n); got != 0 {
		t.Fatalf("%d sync(1) tried in a MicroVM in the error state, which OpenShell refuses", got)
	}
	if got := busy(t, e); got != 0 {
		t.Fatalf("a MicroVM its user let go: busy %d, want the upgrade to go ahead", got)
	}

	// Its VM is gone: nothing runs, nothing waits.
	endIn(t, e, "box", openshell.PhaseProvisioning)
	endIn(t, e, "box", openshell.PhaseError, vmExited)
	if line := feedLine(); !strings.Contains(line, "this OpenShell can neither stop nor start a sandbox in its error state: "+upgrade+
		", then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`") {
		t.Fatalf("the feed's line for a MicroVM whose VM is gone: %q", line)
	}
	if got := busy(t, e); got != 0 {
		t.Fatalf("a MicroVM whose VM is gone: busy %d", got)
	}
}

// A create or a start that DefenseClaw made after a restart's or an
// upgrade's check of the sandboxes ran into that restart unflushed. Each
// now takes the gateway's lifecycle lock over OpenShell's call: while a
// restart or an upgrade holds it, the call is refused with nothing sent
// to OpenShell and the sandbox as it was; it is held only over the call.
func TestCreateAndStartWaitOutAGatewayRestart(t *testing.T) {
	e := newEnv(t, nil)
	dir := t.TempDir()
	held := false
	e.m.opts.StartLock = func() (func(), error) {
		unlock, err := openshell.LockSandboxStart(dir)
		if err == nil {
			held = true
			return func() { held = false; unlock() }, nil
		}
		return nil, err
	}
	restart, err := openshell.LockGatewayLifecycle(context.Background(), dir)
	must(t, err)
	creates := e.fake.Calls(openshelltest.MethodCreateSandbox)
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "box"})
	if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Message, "DefenseClaw is restarting or upgrading the OpenShell gateway") ||
		e.fake.Calls(openshelltest.MethodCreateSandbox) != creates {
		t.Fatalf("a create during a restart = %+v (creates %d)", apiErr, e.fake.Calls(openshelltest.MethodCreateSandbox)-creates)
	}
	restart()
	e.create(sandboxapi.CreateRequest{Name: "box"})
	if held {
		t.Fatal("the create kept the lock after OpenShell's call")
	}
	e.stopBox("box")

	restart, err = openshell.LockGatewayLifecycle(context.Background(), dir)
	must(t, err)
	starts := e.fake.Calls(openshelltest.MethodStartSandbox)
	_, err = e.m.Start(t.Context(), "box", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	if e.fake.Calls(openshelltest.MethodStartSandbox) != starts || e.boxOf("box").phase != audit.SandboxPhaseStopped {
		t.Fatalf("a start during a restart reached OpenShell or moved the sandbox to %s", e.boxOf("box").phase)
	}
	restart()
	e.startBox("box", sandboxapi.StartRequest{})
	if held {
		t.Fatal("the start kept the lock after OpenShell's call")
	}
}
