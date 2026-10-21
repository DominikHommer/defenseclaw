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
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// endedVM is a MicroVM gateway running the sandbox name, whose sync(1)
// execs it counts and fails with the error set.
type endedVM struct {
	*harnessEnv
	mu      sync.Mutex
	syncs   int
	syncErr error
}

func newEndedVM(t *testing.T, name string) *endedVM {
	t.Helper()
	v := &endedVM{harnessEnv: newVMEnv(t, nil)}
	useOpenCode(t, v.harnessEnv)
	v.run()
	v.create(sandboxapi.CreateRequest{Name: name, Harness: "opencode", Copy: true})
	v.watch.waitStarted(t, name)
	v.fake.HandleExec(v.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		v.mu.Lock()
		defer v.mu.Unlock()
		if len(call.Command) == 1 && call.Command[0] == "/bin/sync" {
			v.syncs++
			return openshelltest.ExecResponse{Err: v.syncErr}
		}
		return openshelltest.ExecResponse{Stdout: []byte("exited\nsynced\n")}
	}))
	return v
}

func (v *endedVM) synced() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.syncs
}

func (v *endedVM) failSync(err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.syncErr = err
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

// A completed MicroVM still runs (GAP-0012): the status counts it, so a
// managed switch or the daemon's idle stop of the gateway waits for it,
// and its stop flushes its disk first, as endHarness does only for a ready
// sandbox (OpenShell before 0.1.5 stops a MicroVM without a flush). One
// whose provisioning timed out ran nothing and gets no flush. On docker a
// completed sandbox is an exited container: nothing waits, nothing is
// flushed.
func TestStopFlushesAMicroVMWhoseWorkloadEnded(t *testing.T) {
	e := newEndedVM(t, "donebox")
	endIn(t, e.harnessEnv, "donebox", openshell.PhaseCompleted)
	if got := busy(t, e.harnessEnv); got != 1 {
		t.Fatalf("a completed MicroVM: busy %d, want 1", got)
	}
	atStop := -1
	e.fake.Intercept(func(method string) error {
		if method == openshelltest.MethodStopSandbox {
			atStop = e.synced()
		}
		return nil
	})
	e.stopBox("donebox")
	if atStop != 1 || e.synced() != 1 {
		t.Fatalf("syncs before the stop %d, after %d: want the flush first", atStop, e.synced())
	}
	if got := busy(t, e.harnessEnv); got != 0 {
		t.Fatalf("a stopped MicroVM: busy %d", got)
	}

	e.startBox("donebox", sandboxapi.StartRequest{})
	endIn(t, e.harnessEnv, "donebox", openshell.PhaseError,
		stream.Condition{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"})
	if got := busy(t, e.harnessEnv); got != 0 {
		t.Fatalf("a MicroVM whose provisioning timed out: busy %d", got)
	}
	before := e.synced()
	if _, err := e.m.Stop(t.Context(), "donebox"); err != nil {
		t.Fatalf("stop after a provisioning timeout: %v", err)
	}
	if e.synced() != before {
		t.Fatal("a MicroVM whose provisioning timed out was flushed")
	}

	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dockerdone"})
	endIn(t, d, "dockerdone", openshell.PhaseCompleted)
	if got := busy(t, d); got != 0 {
		t.Fatalf("a completed docker sandbox: busy %d", got)
	}
	n := len(d.execCalls())
	d.stopBox("dockerdone")
	for _, c := range d.execCalls()[n:] {
		if len(c.Command) == 1 && c.Command[0] == "/bin/sync" {
			t.Fatalf("a completed docker sandbox was flushed: %+v", c)
		}
	}
}

// An OpenShell before 0.1.5 (the 0.1.3 of DefenseClaw 1.0.3) neither stops
// nor starts a MicroVM in its error state, and DefenseClaw starts no
// sandbox on it, so the upgrade (per user, or the managed pin migration)
// waited for that MicroVM for ever: its way on said to upgrade first, and
// a delete loses its work. Its stop now flushes the MicroVM's disk before
// OpenShell refuses it, so the restart of the upgrade keeps its work: the
// status no longer counts it, the refusal says so and gives the way on
// after the upgrade, and the feed records it. A stop whose flush fails
// says that too and the upgrade keeps waiting; the next phase change
// counts the MicroVM again.
func TestOldGatewayErrorMicroVMIsFlushedForTheUpgrade(t *testing.T) {
	e := newEndedVM(t, "box")
	connectAtFakeRelease(e.harnessEnv)
	e.fake.SetRelease("0.1.3")
	if _, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Harness: "opencode", Copy: true, Project: e.otherProject("other")}); err == nil {
		t.Fatal("a create on 0.1.3 succeeded")
	}
	if got := e.m.gatewayRelease(); got != "0.1.3" {
		t.Fatalf("gateway release = %q", got)
	}
	upgrade := "upgrade OpenShell 0.1.3 to " + openshell.InstallerVersion + " in place with `defenseclaw sandbox setup --install-openshell`"
	failed := stream.Condition{Type: "Ready", Status: "False", Reason: "ProcessExited", Message: "main process exited with status 1"}
	endIn(t, e.harnessEnv, "box", openshell.PhaseError, failed)
	var line string
	for _, ev := range e.events("box", sandboxapi.ActivityLifecycle, "") {
		if ev.Phase == string(audit.SandboxPhaseError) {
			line = ev.Message
		}
	}
	if !strings.Contains(line, "first `defenseclaw sandbox stop box`, which this OpenShell refuses but which flushes the MicroVM's disk") ||
		!strings.Contains(line, "then "+upgrade+", then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`") {
		t.Fatalf("the feed's line: %q", line)
	}
	if got := busy(t, e.harnessEnv); got != 1 {
		t.Fatalf("a MicroVM in the error state: busy %d", got)
	}
	refused := &types.StatusError{Code: types.ErrorConflict, Message: "sandbox must be Ready to stop (current phase: Error)"}

	// The MicroVM does not answer: nothing could flush it.
	e.failSync(errors.New("exec relay closed"))
	e.fake.FailNext(openshelltest.MethodStopSandbox, refused)
	_, err := e.m.Stop(t.Context(), "box")
	apiErr := wantCode(t, err, sandboxapi.CodeConflict)
	if !strings.Contains(apiErr.Message, "box is in OpenShell's error state") ||
		!strings.Contains(apiErr.Message, "DefenseClaw could not flush its MicroVM's disk either (") || !strings.Contains(apiErr.Message, "exec relay closed") ||
		!strings.HasPrefix(apiErr.Detail, "its MicroVM does not answer, so nothing can flush it: `defenseclaw sandbox stop box` again once it answers flushes it") ||
		!strings.Contains(apiErr.Detail, upgrade+", then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`") {
		t.Fatalf("stop with a failed flush = %+v", apiErr)
	}
	if got := busy(t, e.harnessEnv); got != 1 || e.boxOf("box").rec.FlushedIn != "" {
		t.Fatalf("after a failed flush: busy %d, flushed in %q", got, e.boxOf("box").rec.FlushedIn)
	}

	// It answers: flushed, and the upgrade no longer waits for it.
	e.failSync(nil)
	before := e.synced()
	e.fake.FailNext(openshelltest.MethodStopSandbox, refused)
	_, err = e.m.Stop(t.Context(), "box")
	apiErr = wantCode(t, err, sandboxapi.CodeConflict)
	if e.synced() != before+1 || !strings.Contains(apiErr.Message, "DefenseClaw flushed its MicroVM's disk instead") ||
		strings.Contains(apiErr.Detail, "first `defenseclaw sandbox stop") ||
		!strings.Contains(apiErr.Detail, upgrade+", then `defenseclaw sandbox stop box` and `defenseclaw sandbox start box`") {
		t.Fatalf("stop with a flush = %+v (synced %d times)", apiErr, e.synced()-before)
	}
	if got := busy(t, e.harnessEnv); got != 0 {
		t.Fatalf("a flushed MicroVM in the error state: busy %d", got)
	}
	list, err := e.m.List(t.Context())
	must(t, err)
	for _, v := range list {
		if v.Name == "box" && (v.FlushedIn != "error" || HoldsCompute(v)) {
			t.Fatalf("the view: flushed in %q, holds compute %v", v.FlushedIn, HoldsCompute(v))
		}
	}
	if len(e.events("box", sandboxapi.ActivityLifecycle, keptFlushedReason)) != 1 {
		t.Fatal("the feed does not say the MicroVM was flushed")
	}
	recs, _ := e.m.records.loadAll()
	saved := "none"
	for _, r := range recs {
		if r.Name == "box" {
			saved = r.FlushedIn
		}
	}
	if saved != "error" {
		t.Fatalf("the saved record is flushed in %q", saved)
	}

	// Its next phase counts again.
	endIn(t, e.harnessEnv, "box", openshell.PhaseProvisioning)
	endIn(t, e.harnessEnv, "box", openshell.PhaseError, failed)
	if got := busy(t, e.harnessEnv); got != 1 || e.boxOf("box").rec.FlushedIn != "" {
		t.Fatalf("the next error state: busy %d, flushed in %q", got, e.boxOf("box").rec.FlushedIn)
	}
}
