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
	"slices"
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// A 0.1.3 MicroVM does not flush on stop. An automatic legacy-supervisor
// stop must keep its disk when sync fails, even though the network broker
// needs to be isolated immediately.
func TestLegacyMicroVMAutoStopRequiresAConfirmedFlush(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer openshelltest.ExecResponse
	}{
		{"no sync confirmation", openshelltest.ExecResponse{Stdout: []byte("exited\n")}},
		{"sync exec failed", openshelltest.ExecResponse{Err: errors.New("sync failed")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newVMEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "kept", Copy: true})
			e.addNetworkRule("kept", "direct", "background.example.org", 443)
			b := e.boxOf("kept")
			e.m.mu.Lock()
			b.rec.SessionRelease = "0.1.3"
			e.m.mu.Unlock()
			e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
				if len(call.Command) > 0 && call.Command[0] == "/bin/sync" {
					return openshelltest.ExecResponse{Err: errors.New("sync failed")}
				}
				return tc.answer
			}))
			stops := e.fake.Calls(openshelltest.MethodStopSandbox)
			e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
			e.m.tamperStops.Wait()
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
				t.Fatalf("stopped an unflushed MicroVM: %d stop calls", got-stops)
			}
			if got := e.get("kept"); got.Phase != "ready" || !got.OldSupervisor {
				t.Fatalf("legacy MicroVM was not retained: %+v", got)
			}
			if e.hasRule("kept", "direct") || !b.rec.OldSupervisorNetworkClosed {
				t.Fatalf("legacy MicroVM still has network access: %+v", b.rec)
			}
			if found := e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor); len(found) < 2 ||
				!strings.Contains(found[len(found)-1].Message, "explicitly run `defenseclaw sandbox stop kept`") ||
				!strings.Contains(found[len(found)-1].Message, "loss of unsynced writes") {
				t.Fatalf("no loss-aware stop decision: %+v", found)
			}
			if tc.name == "no sync confirmation" {
				// A later confirmed flush lets the automatic stop finish. The
				// next session restores only its create-time policy.
				e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, _ openshelltest.ExecCall) openshelltest.ExecResponse {
					return openshelltest.ExecResponse{Stdout: []byte("exited\nsynced\n")}
				}))
				must(t, e.m.Reconcile(t.Context()))
				e.m.tamperStops.Wait()
				if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor {
					t.Fatalf("confirmed flush did not stop the old session: %+v", got)
				}
				e.startBox("kept", sandboxapi.StartRequest{})
				if !e.hasRule("kept", "defenseclaw_egress") || e.hasRule("kept", "direct") || b.rec.OldSupervisorNetworkClosed {
					t.Fatalf("new session did not restore its create-time network: %+v", b.rec)
				}
			}
		})
	}
}

// TestAHostLeftOnAnOlderOpenShellUpgradesInPlace: DefenseClaw 1.0.0 to
// 1.0.3 left hosts on OpenShell 0.1.1 to 0.1.3, whose network broker can let
// a sandbox's connections bypass its policy (NVIDIA/OpenShell#4494). The
// daemon still connects to such a gateway and drives the sandboxes there
// (status, stop), so their work is kept, but creates and starts none,
// naming the in-place upgrade. A sandbox whose session runs that release's
// supervisor is stopped (GAP-0415) and starts again on the upgraded gateway
// only.
func TestAHostLeftOnAnOlderOpenShellUpgradesInPlace(t *testing.T) {
	e := newEnv(t, nil)
	e.m.opts.Connect = func(ctx context.Context) (*Gateway, error) {
		h, err := e.client.Health(ctx)
		if err != nil {
			return nil, err
		}
		gw := *e.gw
		gw.Version = h.RawVersion
		return &gw, nil
	}
	e.create(sandboxapi.CreateRequest{Name: "kept"})
	if got := e.boxOf("kept").rec.SessionRelease; got != openshell.SupportedMin {
		t.Fatalf("session release = %q, want %s", got, openshell.SupportedMin)
	}
	oldSupervisor := func() []sandboxapi.ActivityEvent {
		return e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor)
	}
	if n := len(oldSupervisor()); n != 0 || slices.Contains(e.get("kept").Warnings, oldSupervisorWarning) {
		t.Fatalf("a session on %s is named: %d findings, warnings %v", openshell.SupportedMin, n, e.get("kept").Warnings)
	}

	// The host as 1.0.3 left it: its gateway runs 0.1.3.
	e.fake.SetRelease("0.1.3")
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "fresh", Project: e.otherProject("other")})
	apiErr := wantCode(t, err, sandboxapi.CodeUnavailable)
	if !strings.Contains(apiErr.Message, "OpenShell 0.1.3 runs no DefenseClaw sandbox") || !strings.Contains(apiErr.Message, "NVIDIA/OpenShell#4494") ||
		apiErr.Detail != "upgrade OpenShell 0.1.3 to "+openshell.InstallerVersion+" in place with `defenseclaw sandbox setup --install-openshell`" {
		t.Fatalf("create on 0.1.3 = %+v", apiErr)
	}
	if e.boxOf("fresh") != nil {
		t.Fatal("the refused create left a sandbox behind")
	}
	// A session that starts on it (outside DefenseClaw) runs its
	// supervisor: DefenseClaw stops it (GAP-0415), keeping its work, and the
	// old gateway starts it no more.
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseProvisioning})
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseReady})
	e.m.tamperStops.Wait()
	found := oldSupervisor()
	if len(found) != 1 || found[0].Severity != "HIGH" || !strings.Contains(found[0].Message, "kept's session started on OpenShell 0.1.3") ||
		!strings.Contains(found[0].Message, "DefenseClaw closes a legacy MicroVM's network and stops it after a confirmed disk flush; if sync fails, it keeps the VM and an explicit `defenseclaw sandbox stop kept` may lose unsynced writes; upgrade OpenShell 0.1.3 to "+openshell.InstallerVersion) ||
		!strings.HasSuffix(found[0].Message, "then `defenseclaw sandbox start kept` starts it on that release's supervisor") {
		t.Fatalf("old-supervisor findings = %+v", found)
	}
	if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor || slices.Contains(got.Warnings, oldSupervisorWarning) {
		t.Fatalf("a session on the 0.1.3 supervisor: phase %s, old supervisor %v, warnings %v", got.Phase, got.OldSupervisor, got.Warnings)
	}
	_, err = e.m.Start(t.Context(), "kept", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Message, "OpenShell 0.1.3 runs no DefenseClaw sandbox") {
		t.Fatalf("start on 0.1.3 = %+v", apiErr)
	}

	// The in-place upgrade: the start goes on the new release's supervisor.
	e.fake.SetRelease(openshell.InstallerVersion)
	e.startBox("kept", sandboxapi.StartRequest{})
	if got := e.boxOf("kept").rec.SessionRelease; got != openshell.InstallerVersion {
		t.Fatalf("session release after the upgrade = %q", got)
	}
	if slices.Contains(e.get("kept").Warnings, oldSupervisorWarning) || len(oldSupervisor()) != 1 {
		t.Fatalf("after the upgrade: warnings %v, findings %d", e.get("kept").Warnings, len(oldSupervisor()))
	}
}

// A record from before DefenseClaw kept the session's release names no
// release, and the managed way on is the administrator's.
func TestOldSupervisorWordsForARecordWithoutARelease(t *testing.T) {
	msg := oldSupervisorMessage("box", "", "")
	if !strings.Contains(msg, "box's session started before DefenseClaw kept the OpenShell release a session starts on, so it may run a supervisor older than "+openshell.SupportedMin) ||
		!strings.HasSuffix(msg, "DefenseClaw closes a legacy MicroVM's network and stops it after a confirmed disk flush; if sync fails, it keeps the VM and an explicit `defenseclaw sandbox stop box` may lose unsynced writes; `defenseclaw sandbox start box` (or `connect`) starts it again on this gateway's supervisor") {
		t.Fatalf("message = %q", msg)
	}
	e := newEnv(t, nil)
	if got := e.m.upgradeWayOn(openshell.SupportedMin); got != "" {
		t.Fatalf("upgrade way on %s = %q", openshell.SupportedMin, got)
	}
	if got := e.m.upgradeWayOn("dev"); got != "" {
		t.Fatalf("upgrade way on an unreadable release = %q", got)
	}
}

// TestAnOldSupervisorIsStoppedBeforeAnySandboxRunsOnIt (GAP-0415): a session
// that began on the supervisor of an OpenShell older than SupportedMin, or
// one a 1.0.3 record names no release for, keeps that supervisor's network
// broker, which can let its connections bypass its policy, for as long as it
// runs, whatever the gateway runs now. DefenseClaw stops it as soon as it
// sees it, also on an upgraded gateway and for a restarted daemon, and the
// next start runs the gateway's own supervisor. A stop that fails keeps the
// session's release, says so, names it in the view for the CLI, and is tried again on each
// reconcile until the session stops.
func TestAnOldSupervisorIsStoppedBeforeAnySandboxRunsOnIt(t *testing.T) {
	e := newEnv(t, nil)
	e.m.opts.Connect = func(ctx context.Context) (*Gateway, error) {
		h, err := e.client.Health(ctx)
		if err != nil {
			return nil, err
		}
		gw := *e.gw
		gw.Version = h.RawVersion
		return &gw, nil
	}
	e.create(sandboxapi.CreateRequest{Name: "kept"})
	sight := func(release string) {
		t.Helper()
		b := e.boxOf("kept")
		e.m.mu.Lock()
		b.rec.SessionRelease = release
		e.m.mu.Unlock()
		// The daemon restarted on 1.0.4 republishes what it finds.
		e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
		e.m.tamperStops.Wait()
	}
	finding := func(text string) int {
		n := 0
		for _, ev := range e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor) {
			if strings.Contains(ev.Message, text) {
				n++
			}
		}
		return n
	}

	// A record 1.0.3 wrote names no release: the session is stopped on the
	// upgraded gateway, and its start runs that gateway's supervisor.
	sight("")
	if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor {
		t.Fatalf("a 1.0.3 session on a %s gateway: phase %s, old supervisor %v", openshell.SupportedMin, got.Phase, got.OldSupervisor)
	}
	if finding("kept's session started before DefenseClaw kept the OpenShell release") != 1 ||
		finding("`defenseclaw sandbox start kept` (or `connect`) starts it again on this gateway's supervisor") != 1 {
		t.Fatalf("findings = %+v", e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
	}
	e.startBox("kept", sandboxapi.StartRequest{})
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor || e.boxOf("kept").rec.SessionRelease != openshell.SupportedMin {
		t.Fatalf("after the start: phase %s, old supervisor %v, release %q", got.Phase, got.OldSupervisor, e.boxOf("kept").rec.SessionRelease)
	}

	// A session on 0.1.3 whose stop fails: it still runs on that supervisor,
	// which the failed stop does not mistake for a new session, the feed
	// says so, and the view names it.
	e.fake.FailNext(openshelltest.MethodStopSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "the gateway is busy"})
	sight("0.1.3")
	got := e.get("kept")
	if got.Phase != "ready" || !got.OldSupervisor || !slices.Contains(got.Warnings, oldSupervisorWarning) || e.boxOf("kept").rec.SessionRelease != "0.1.3" {
		t.Fatalf("after a failed stop: phase %s, old supervisor %v, warnings %v, release %q", got.Phase, got.OldSupervisor, got.Warnings, e.boxOf("kept").rec.SessionRelease)
	}
	if finding("DefenseClaw could not stop kept, whose session still runs the supervisor of OpenShell 0.1.3") != 1 {
		t.Fatalf("findings = %+v", e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor))
	}
	// The daemon's next periodic reconcile, which forces no transition on a
	// sandbox still ready, tries the stop again, and it stops it.
	must(t, e.m.Reconcile(t.Context()))
	e.m.tamperStops.Wait()
	if got := e.get("kept"); got.Phase != "stopped" || got.OldSupervisor {
		t.Fatalf("the next reconcile: phase %s, old supervisor %v", got.Phase, got.OldSupervisor)
	}

	// A session on the gateway's own supervisor is left running.
	e.startBox("kept", sandboxapi.StartRequest{})
	sight(openshell.SupportedMin)
	if got := e.get("kept"); got.Phase != "ready" || got.OldSupervisor {
		t.Fatalf("a session on %s: phase %s, old supervisor %v", openshell.SupportedMin, got.Phase, got.OldSupervisor)
	}
}

// legacyMicroVMWithBrokenSync is a ready 0.1.3 MicroVM named name with a
// direct network rule, whose guest sync(1) fails.
func legacyMicroVMWithBrokenSync(t *testing.T, name string) (*harnessEnv, *box) {
	t.Helper()
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: name, Copy: true})
	e.addNetworkRule(name, "direct", "background.example.org", 443)
	b := e.boxOf(name)
	e.m.mu.Lock()
	b.rec.SessionRelease = "0.1.3"
	e.m.mu.Unlock()
	e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if len(call.Command) > 0 && call.Command[0] == "/bin/sync" {
			return openshelltest.ExecResponse{Err: errors.New("sync failed")}
		}
		return openshelltest.ExecResponse{Stdout: []byte("exited\n")}
	}))
	return e, b
}

// findingsSaying are the sandbox's old-supervisor findings that contain text.
func findingsSaying(e *harnessEnv, name, text string) []sandboxapi.ActivityEvent {
	var out []sandboxapi.ActivityEvent
	for _, ev := range e.events(name, sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor) {
		if strings.Contains(ev.Message, text) {
			out = append(out, ev)
		}
	}
	return out
}

// A legacy MicroVM whose sync fails is kept only while its network is
// proven closed. When its containment fails too (a gateway-global policy,
// under which DefenseClaw cannot change the sandbox's rules; OpenShell
// refusing the policy update; a refusal that only comes after the first
// containment succeeded), the automatic stop goes ahead without the flush
// and the feed says what that may have lost: a legacy supervisor never
// keeps running with open egress (fail closed).
func TestLegacyMicroVMWhoseNetworkStaysOpenIsStoppedWithoutAFlush(t *testing.T) {
	refuseUpdates := func(e *harnessEnv) {
		e.fake.Intercept(func(method string) error {
			if method == openshelltest.MethodUpdateConfig {
				return &types.StatusError{Code: types.ErrorConflict, Message: "policy update refused"}
			}
			return nil
		})
	}
	for _, tc := range []struct {
		name string
		// before breaks containment before the session is seen ready;
		// later, when set, only after a first containment kept the VM.
		before, later func(e *harnessEnv)
		cause         string
	}{
		{name: "gateway-global policy", before: func(e *harnessEnv) { e.fake.SetGlobalPolicy(&openshell.SandboxPolicy{Version: 1}) },
			cause: "gateway-global policy"},
		{name: "policy update refused", before: refuseUpdates, cause: "policy update refused"},
		{name: "global policy after the VM was kept", later: func(e *harnessEnv) { e.fake.SetGlobalPolicy(&openshell.SandboxPolicy{Version: 1}) },
			cause: "gateway-global policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, b := legacyMicroVMWithBrokenSync(t, "leaky")
			if tc.before != nil {
				tc.before(e)
			}
			stops := e.fake.Calls(openshelltest.MethodStopSandbox)
			e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
			e.m.tamperStops.Wait()
			if tc.later != nil {
				if got := e.get("leaky"); got.Phase != "ready" || !b.rec.OldSupervisorNetworkClosed {
					t.Fatalf("a contained VM was not kept first: %+v", got)
				}
				tc.later(e)
				must(t, e.m.Reconcile(t.Context()))
				e.m.tamperStops.Wait()
			}
			if got := e.fake.Calls(openshelltest.MethodStopSandbox); got == stops {
				t.Fatalf("a legacy MicroVM whose network could not be closed kept running: %+v", e.get("leaky"))
			}
			if got := e.get("leaky"); got.Phase != "stopped" {
				t.Fatalf("legacy MicroVM with an open network = %+v", got)
			}
			if got := e.events("leaky", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 1 {
				t.Fatalf("the unflushed stop was not reported once: %+v", got)
			}
			if got := findingsSaying(e, "leaky", "stopped leaky's legacy MicroVM without a confirmed disk flush"); len(got) != 1 ||
				!strings.Contains(got[0].Message, tc.cause) || got[0].Severity != "HIGH" {
				t.Fatalf("no loss-aware finding naming %q: %+v", tc.cause, got)
			}
			if tc.later == nil {
				if got := findingsSaying(e, "leaky", "DefenseClaw kept leaky's"); len(got) != 0 {
					t.Fatalf("said the VM was kept: %+v", got)
				}
			}
		})
	}
}

// An automatic legacy stop that the unconfirmed flush aborted stopped
// nothing: the feed says once that the VM was kept, however often reconcile
// retries, and never that a stop lost its writes. A manual stop that
// OpenShell refused lost nothing either; one it took says so.
func TestAnAbortedLegacyAutoStopSaysItKeptTheVMOnce(t *testing.T) {
	e, b := legacyMicroVMWithBrokenSync(t, "kept")
	stops := e.fake.Calls(openshelltest.MethodStopSandbox)
	e.m.lifecycle(t.Context(), b, audit.SandboxPhaseReady, audit.SandboxTriggerWatch, true, nil, nil)
	e.m.tamperStops.Wait()
	for range 3 {
		must(t, e.m.Reconcile(t.Context()))
		e.m.tamperStops.Wait()
	}
	if got := e.fake.Calls(openshelltest.MethodStopSandbox); got != stops {
		t.Fatalf("stopped an unflushed, contained MicroVM: %d stop calls", got-stops)
	}
	if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 0 {
		t.Fatalf("an aborted stop was reported as a stop that lost writes: %+v", got)
	}
	if got := findingsSaying(e, "kept", "DefenseClaw kept kept's legacy MicroVM"); len(got) != 1 {
		t.Fatalf("the kept VM was not reported exactly once over four attempts: %+v", got)
	}

	// The user accepts the loss: OpenShell refuses the first stop, which
	// lost nothing, and takes the second, which says what it may have lost.
	e.fake.FailNext(openshelltest.MethodStopSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "stop refused"})
	if _, err := e.m.Stop(t.Context(), "kept"); err == nil {
		t.Fatal("the refused stop succeeded")
	}
	if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 0 {
		t.Fatalf("a refused stop was reported as one that lost writes: %+v", got)
	}
	e.stopBox("kept")
	if got := e.events("kept", sandboxapi.ActivityLifecycle, "stop_unflushed"); len(got) != 1 {
		t.Fatalf("the explicit unflushed stop was not reported once: %+v", got)
	}
}
