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

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// rel-1-0-2:GAP-0462: after an rpm upgrade deferred the daemon's restart,
// `sandbox stop` of the last running sandbox failed with "wait ... to stop:
// context canceled (last poll: ... connection refused 127.0.0.1:17670)"
// although the sandbox stopped. Its phase left the running ones before
// OpenShell said it stopped, so the supervision stopped the account's
// OpenShell gateway and exited for the restart under the stop's wait. A
// stop or delete in flight now holds both off; the restart follows once it
// ends.
func TestSandboxDaemonDeferredRestartWaitsForAStop(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	if err := os.WriteFile(f.exe, []byte("v2-upgraded"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.running.Store(1)
	if stop, _ := f.d.check(ctx); stop || !f.d.pendingRestart.Load() {
		t.Fatal("the upgrade was not deferred while a sandbox runs")
	}
	f.os.holder.Store(int64(os.Getuid()))
	f.d.openShellUsed.Store(time.Now().Add(-2 * openShellGatewayLinger).UnixNano())

	// The sandbox is stopping: no longer counted as running, the stop still
	// waits on the gateway.
	f.running.Store(0)
	f.d.stops.Add(1)
	if stop, err := f.d.check(ctx); stop || err != nil {
		t.Fatalf("restarted under a stop in flight: %v %v", stop, err)
	}
	if n := f.os.stopped.Load(); n != 0 {
		t.Fatalf("stopped the account's gateway under a stop in flight (%d)", n)
	}
	f.d.stops.Add(-1)
	if stop, err := f.d.check(ctx); !stop || !errors.Is(err, ErrSandboxDaemonRestart) {
		t.Fatalf("after the stop: %v %v, want the deferred restart", stop, err)
	}
	if n := f.os.stopped.Load(); n != 1 {
		t.Fatalf("after the stop the idle gateway was stopped %d times", n)
	}
}

// Stop and delete hold the in-flight count for their whole call: here the
// readying of the account's gateway, which runs before the manager's stop
// or delete and its wait.
func TestSandboxDaemonStopAndDeleteCountAsInFlight(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	var during []int64
	f.os.prepare = func(sandboxrelay.DaemonSettings) (bool, error) {
		during = append(during, f.d.stops.Load())
		return false, nil
	}
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	_, _ = ctl.Stop(ctx, "kept1")
	_, _ = ctl.Delete(ctx, "kept1", sandboxapi.DeleteRequest{})
	if len(during) != 2 || during[0] != 1 || during[1] != 1 {
		t.Fatalf("in-flight count while the stop and the delete ran: %v, want [1 1]", during)
	}
	if n := f.d.stops.Load(); n != 0 {
		t.Fatalf("in-flight count after them: %d", n)
	}
}

// The other half of GAP-0462: right after the restart, `sandbox status`
// said "your organization does not let you run sandboxes
// (openshell.admin.allowed)" and a strict, deny-all policy for a sandbox the
// organization allows: the closed start-up floor the manager judges with
// until a confirmed registration's floor is adopted. A status or list made
// while it is still in force confirms the registrations again first.
func TestSandboxDaemonStatusConfirmsAgainOnTheClosedFloor(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	floor := config.OpenShellAdminConfig{MinProfile: "balanced", RequestAccess: "it-help@example.com"}
	// On file but not confirmed: the managed gateway did not answer at start.
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Floor: floor, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if admin := f.d.config().OpenShell.Admin; admin.Allowed == nil || *admin.Allowed {
		t.Fatalf("the fixture does not start on the closed floor: %+v", admin)
	}
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}

	// Still no answer: the closed floor stays, nothing else changes.
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{}, errors.New("connect: connection refused")
	}
	_, _ = ctl.Get(ctx, "dc-a")
	if admin := f.d.config().OpenShell.Admin; admin.Allowed == nil || *admin.Allowed {
		t.Fatalf("adopted an unconfirmed registration's floor: %+v", admin)
	}

	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 3}, nil
	}
	_, _ = ctl.Get(ctx, "dc-a")
	admin := f.d.config().OpenShell.Admin
	if admin.Allowed != nil || admin.MinProfile != "balanced" {
		t.Fatalf("status kept the closed floor after the registration was confirmed: %+v", admin)
	}
	if r, _ := f.d.regs.get("dc-a"); !r.Confirmed {
		t.Fatal("the registration was not confirmed")
	}

	// A list confirms too; a revoked registration's sandbox is stopped as at
	// start, and its floor is never adopted.
	g := newSandboxDaemonFixture(t)
	g.run(t)
	if err := g.d.regs.put(daemonRegistration{ID: "reg-2", Sandbox: "dc-b", Floor: floor, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	g.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Revoked: true, RevokedReason: "profile removed"}, nil
	}
	gctl := &managedSandboxController{Manager: g.d.rt.manager, d: g.d}
	_, _ = gctl.List(ctx)
	if r, _ := g.d.regs.get("dc-b"); !r.Revoked {
		t.Fatalf("the revoked registration was not marked: %+v", r)
	}
	if admin := g.d.config().OpenShell.Admin; admin.Allowed == nil || *admin.Allowed {
		t.Fatalf("adopted a revoked registration's floor: %+v", admin)
	}
}
