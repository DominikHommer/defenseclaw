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

package openshell_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// TestMayHoldCompute: a gateway stop waits for every phase but stopped and
// deleting, an unknown one and one this build does not name included; a
// sandbox whose workload ended (completed, error) holds nothing only where
// the driver's stop flushes (docker), since a MicroVM keeps running after
// its workload ends (GAP-0012). The workload of one in the error state
// ended, but where OpenShell could not poll its VM's process.
func TestMayHoldCompute(t *testing.T) {
	for _, tc := range []struct {
		phase       openshell.SandboxPhase
		stopFlushes bool
		holding     bool
	}{
		{openshell.PhaseReady, true, true},
		{openshell.PhaseProvisioning, false, true},
		{openshell.PhaseStarting, false, true},
		{openshell.PhaseStopping, false, true},
		{openshell.PhaseUnknown, false, true},
		{"Hibernating", false, true},
		{"", true, true},
		{openshell.PhaseCompleted, false, true},
		{openshell.PhaseError, false, true},
		{openshell.PhaseCompleted, true, false},
		{openshell.PhaseError, true, false},
		{openshell.PhaseStopped, false, false},
		{openshell.PhaseDeleting, false, false},
	} {
		if got := openshell.MayHoldCompute(tc.phase, tc.stopFlushes); got != tc.holding {
			t.Errorf("MayHoldCompute(%q, %v) = %v", tc.phase, tc.stopFlushes, got)
		}
	}
	for _, tc := range []struct {
		phase openshell.SandboxPhase
		said  string
		ended bool
	}{
		{openshell.PhaseCompleted, "", true},
		{openshell.PhaseError, "", true},
		{openshell.PhaseError, "MainProcessFailed: Canonical main process exited with status 1", true},
		{openshell.PhaseError, "ProcessExited: VM process exited with status 1", true},
		{openshell.PhaseError, "ProcessPollFailed: Bad file descriptor", false},
		{openshell.PhaseReady, "", false},
		{openshell.PhaseStopped, "", false},
		{openshell.PhaseUnknown, "", false},
	} {
		if openshell.WorkloadEnded(tc.phase, tc.said) != tc.ended {
			t.Errorf("WorkloadEnded(%q, %q) = %v", tc.phase, tc.said, !tc.ended)
		}
	}
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if openshell.EndedSettled(time.Time{}, at) || openshell.EndedSettled(at, at.Add(openshell.EndedSettle-time.Second)) ||
		!openshell.EndedSettled(at, at.Add(openshell.EndedSettle)) {
		t.Error("EndedSettled: a MicroVM settles EndedSettle after its workload ended, and one not known since when never")
	}
}

// settleTime is a fake clock for the wait for MicroVMs whose workload
// ended: every sleep moves it on, and onSleep (when set) runs after each.
type settleTime struct {
	mu      sync.Mutex
	now     time.Time
	slept   time.Duration
	onSleep func(slept time.Duration)
}

func fakeSettleClock(t *testing.T) *settleTime {
	t.Helper()
	c := &settleTime{now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	openshell.SetSettleClock(t, func() time.Time {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.now
	}, func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		c.now = c.now.Add(d)
		c.slept += d
		slept, f := c.slept, c.onSleep
		c.mu.Unlock()
		if f != nil {
			f(slept)
		}
		return nil
	})
	return c
}

func (c *settleTime) waited() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.slept
}

// computeGateway is a gateway on driver d with a sandbox in each phase,
// conds giving the conditions of some.
func computeGateway(t *testing.T, d openshell.ComputeDriver, phases map[string]openshell.SandboxPhase, conds map[string]v1.SandboxCondition) (openshell.Client, *openshelltest.Fake) {
	t.Helper()
	f := openshelltest.New(openshelltest.WithDriver(d))
	c := f.Client(openshell.ClientOptions{})
	for name, phase := range phases {
		if _, err := c.CreateSandbox(context.Background(), name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := f.SetPhase(openshell.DefaultWorkspace, name, phase); err != nil {
			t.Fatal(err)
		}
		if cond, ok := conds[name]; ok {
			setConditions(t, f, name, cond)
		}
	}
	return c, f
}

func setConditions(t *testing.T, f *openshelltest.Fake, name string, conds ...v1.SandboxCondition) {
	t.Helper()
	sb, err := f.Sandboxes().Get(context.Background(), openshell.DefaultWorkspace, name)
	if err != nil {
		t.Fatal(err)
	}
	sb.Status.Conditions = conds
	sb.ResourceVersion++
	f.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
}

// execsIn names the sandboxes the fake was asked to run a command in.
func execsIn(f *openshelltest.Fake) []string {
	var out []string
	for _, c := range f.ExecCalls() {
		out = append(out, c.Sandbox)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

var (
	failedMain = v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "MainProcessFailed", Message: "Canonical main process exited with status 1"}
	unpolled   = v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "ProcessPollFailed", Message: "Bad file descriptor"}
	timedOut   = v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"}
)

// The fake does what OpenShell does to a MicroVM whose workload ended: it
// runs no command in it (exec only in a ready sandbox), and its stop
// returns a completed one, or one whose main process failed, as it is.
func TestFakeLeavesAnEndedSandboxAsOpenShellDoes(t *testing.T) {
	c, f := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{
		"dc-done": openshell.PhaseCompleted, "dc-failed": openshell.PhaseError, "dc-starting": openshell.PhaseStarting, "dc-up": openshell.PhaseReady,
	}, nil)
	for _, name := range []string{"dc-done", "dc-failed", "dc-starting"} {
		if _, err := c.Exec(context.Background(), name, []string{"/bin/sync"}, openshell.ExecOptions{Attempts: 1}); err == nil || !strings.Contains(err.Error(), "sandbox is not ready") {
			t.Errorf("exec in %s: %v, want OpenShell's refusal", name, err)
		}
	}
	if _, err := c.Exec(context.Background(), "dc-up", []string{"/bin/sync"}, openshell.ExecOptions{Attempts: 1}); err != nil {
		t.Errorf("exec in a ready sandbox: %v", err)
	}
	sb, err := c.StopSandbox(context.Background(), "dc-done")
	if err != nil || sb.Status.Phase != openshell.PhaseCompleted {
		t.Fatalf("stop of a completed sandbox: %+v, %v", sb, err)
	}
	sb, err = f.Sandboxes().Get(context.Background(), openshell.DefaultWorkspace, "dc-failed")
	if err != nil {
		t.Fatal(err)
	}
	code := int32(1)
	sb.Status.ExitCode = &code
	sb.ResourceVersion++
	f.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
	if sb, err = c.StopSandbox(context.Background(), "dc-failed"); err != nil || sb.Status.Phase != openshell.PhaseError {
		t.Fatalf("stop of a failed main process: %+v, %v", sb, err)
	}
}

// TestPrepareUpgradeWaitsForEveryMicroVMThatMayHoldCompute: on the MicroVM
// driver the upgrade's gateway restart stops every sandbox, so a MicroVM
// starting, stopping, in a phase OpenShell does not name, or in the error
// state with its VM not polled refuses it at once, as a ready one does.
// One whose workload ended (completed, or the error state that an
// OpenShell before 0.1.5 cannot stop) still runs its VM, and nothing in
// OpenShell can flush it: the upgrade waits EndedSettle for its guest to
// write its disk back and execs nothing in it. One started again during
// the wait refuses; a phase change starts the wait over; a wait cut short
// refuses. One whose provisioning timed out ran nothing, and is not waited
// for. On docker none of this applies.
func TestPrepareUpgradeWaitsForEveryMicroVMThatMayHoldCompute(t *testing.T) {
	pull := func(context.Context) error { return nil }
	clock := fakeSettleClock(t)

	for _, tc := range []struct {
		phase openshell.SandboxPhase
		cond  *v1.SandboxCondition
	}{
		{openshell.PhaseStarting, nil}, {openshell.PhaseStopping, nil}, {openshell.PhaseUnknown, nil}, {"Hibernating", nil},
		{openshell.PhaseProvisioning, nil}, {openshell.PhaseReady, nil}, {openshell.PhaseError, &unpolled},
	} {
		conds := map[string]v1.SandboxCondition{}
		if tc.cond != nil {
			conds["dc-x"] = *tc.cond
		}
		c, _ := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": tc.phase, "dc-off": openshell.PhaseStopped, "dc-done": openshell.PhaseCompleted}, conds)
		before := clock.waited()
		err := openshell.PrepareUpgrade(context.Background(), c, pull)
		if !errors.Is(err, openshell.ErrSandboxesRunning) || !strings.Contains(err.Error(), "(dc-x): stop them first with `defenseclaw sandbox stop NAME`") {
			t.Errorf("a MicroVM in phase %q: %v", tc.phase, err)
		}
		if clock.waited() != before {
			t.Errorf("a MicroVM in phase %q: the refusal waited %s first", tc.phase, clock.waited()-before)
		}
	}

	ended := map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted, "dc-failed": openshell.PhaseError, "dc-off": openshell.PhaseStopped}
	c, f := computeGateway(t, openshell.DriverVM, ended, map[string]v1.SandboxCondition{"dc-failed": failedMain})
	before := clock.waited()
	if err := openshell.PrepareUpgrade(context.Background(), c, pull); err != nil {
		t.Fatalf("ended MicroVMs: %v", err)
	}
	if w := clock.waited() - before; w < openshell.EndedSettle || w > openshell.EndedSettle+10*time.Second {
		t.Fatalf("the upgrade waited %s for the ended MicroVMs, want %s", w, openshell.EndedSettle)
	}
	if got := execsIn(f); len(got) != 0 {
		t.Fatalf("the upgrade ran commands in %v, which OpenShell refuses", got)
	}

	// Started again during the wait: it runs, and refuses.
	c, f = computeGateway(t, openshell.DriverVM, ended, nil)
	clock.onSleep = func(time.Duration) { _ = f.SetPhase(openshell.DefaultWorkspace, "dc-done", openshell.PhaseReady) }
	err := openshell.PrepareUpgrade(context.Background(), c, pull)
	clock.onSleep = nil
	if !errors.Is(err, openshell.ErrSandboxesRunning) || !strings.Contains(err.Error(), "(dc-done): stop them first") {
		t.Fatalf("a MicroVM started during the wait: %v", err)
	}

	// Completed, then in the error state: the wait starts over.
	c, f = computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted}, nil)
	clock.onSleep = func(slept time.Duration) {
		if sb, _ := f.Sandboxes().Get(context.Background(), openshell.DefaultWorkspace, "dc-done"); sb.Status.Phase == openshell.PhaseCompleted && slept-before >= time.Minute {
			_ = f.SetPhase(openshell.DefaultWorkspace, "dc-done", openshell.PhaseError)
		}
	}
	before = clock.waited()
	err = openshell.PrepareUpgrade(context.Background(), c, pull)
	clock.onSleep = nil
	if w := clock.waited() - before; err != nil || w < time.Minute+openshell.EndedSettle {
		t.Fatalf("a MicroVM whose phase changed during the wait: %v after %s", err, w)
	}

	// A wait cut short refuses.
	c, _ = computeGateway(t, openshell.DriverVM, ended, nil)
	ctx, cancel := context.WithCancel(context.Background())
	clock.onSleep = func(time.Duration) { cancel() }
	err = openshell.PrepareUpgrade(ctx, c, pull)
	clock.onSleep = nil
	if !errors.Is(err, openshell.ErrSandboxesRunning) || !strings.Contains(err.Error(), "the wait for the MicroVMs whose workload ended to write their disks back ended") {
		t.Fatalf("a wait cut short: %v", err)
	}

	// Provisioning that timed out: nothing ran in it since its last stop.
	c, f = computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-timeout": openshell.PhaseError}, map[string]v1.SandboxCondition{"dc-timeout": timedOut})
	before = clock.waited()
	if err := openshell.PrepareUpgrade(context.Background(), c, pull); err != nil || len(execsIn(f)) != 0 || clock.waited() != before {
		t.Fatalf("a MicroVM whose provisioning timed out: %v, ran in %v, waited %s", err, execsIn(f), clock.waited()-before)
	}

	// Docker keeps its sandboxes through the restart.
	pulls := 0
	c, f = computeGateway(t, openshell.DriverDocker, map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted, "dc-x": openshell.PhaseStarting}, nil)
	before = clock.waited()
	if err := openshell.PrepareUpgrade(context.Background(), c, func(context.Context) error { pulls++; return nil }); err != nil || pulls != 1 || len(execsIn(f)) != 0 || clock.waited() != before {
		t.Fatalf("docker: %v, pulled %d, ran in %v, waited %s", err, pulls, execsIn(f), clock.waited()-before)
	}
}

// TestFlushSandboxesWaitsForEndedMicroVMs: a gateway restart that
// DefenseClaw makes (doctor --fix, setup) on the MicroVM driver applies the
// gate the upgrade does. Before, it flushed only the ready sandboxes: a
// MicroVM whose workload ended was restarted under at once (with no ready
// sandbox, nothing at all came first), and one starting or stopping too.
// Now it waits EndedSettle for an ended MicroVM's guest to write its disk
// back, execs nothing in it, syncs the ready ones after the wait, right
// before the restart, and refuses at once for one that may run work no
// flush reaches. A list that fails during the wait refuses. Docker
// restarts at once.
func TestFlushSandboxesWaitsForEndedMicroVMs(t *testing.T) {
	clock := fakeSettleClock(t)
	var syncedAt []time.Duration
	c, f := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{
		"dc-up": openshell.PhaseReady, "dc-done": openshell.PhaseCompleted, "dc-failed": openshell.PhaseError, "dc-off": openshell.PhaseStopped,
	}, map[string]v1.SandboxCondition{"dc-failed": failedMain})
	f.HandleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
		syncedAt = append(syncedAt, clock.waited())
		return openshelltest.ExecResponse{}
	})
	if err := openshell.FlushSandboxes(context.Background(), c); err != nil {
		t.Fatalf("ended MicroVMs and a ready one: %v", err)
	}
	if got := execsIn(f); !slices.Equal(got, []string{"dc-up"}) {
		t.Fatalf("ran commands in %v, want only the ready one", got)
	}
	if len(syncedAt) != 1 || syncedAt[0] < openshell.EndedSettle {
		t.Fatalf("the ready sandbox was synced at %v, want once, after the %s wait", syncedAt, openshell.EndedSettle)
	}

	// Only ended ones, no ready one: the restart still waits.
	c, f = computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted}, nil)
	before := clock.waited()
	if err := openshell.FlushSandboxes(context.Background(), c); err != nil || clock.waited()-before < openshell.EndedSettle || len(execsIn(f)) != 0 {
		t.Fatalf("only a completed MicroVM: %v, waited %s, ran in %v", err, clock.waited()-before, execsIn(f))
	}

	for _, phase := range []openshell.SandboxPhase{openshell.PhaseStarting, openshell.PhaseStopping, openshell.PhaseProvisioning, openshell.PhaseUnknown} {
		c, f := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": phase, "dc-up": openshell.PhaseReady, "dc-done": openshell.PhaseCompleted}, nil)
		before := clock.waited()
		err := openshell.FlushSandboxes(context.Background(), c)
		if !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), "(dc-x, "+strings.ToLower(string(phase))+"): a MicroVM that is starting, stopping") {
			t.Errorf("a MicroVM in phase %q: %v", phase, err)
		}
		if clock.waited() != before || len(execsIn(f)) != 0 {
			t.Errorf("a MicroVM in phase %q: waited %s, ran in %v before the refusal", phase, clock.waited()-before, execsIn(f))
		}
	}
	c, _ = computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": openshell.PhaseError}, map[string]v1.SandboxCondition{"dc-x": unpolled})
	if err := openshell.FlushSandboxes(context.Background(), c); !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), "(dc-x, error)") {
		t.Errorf("a MicroVM whose VM was not polled: %v", err)
	}

	// The list fails during the wait.
	c, f = computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted}, nil)
	clock.onSleep = func(time.Duration) { f.FailNext(openshelltest.MethodListSandboxes, errors.New("gateway busy")) }
	err := openshell.FlushSandboxes(context.Background(), c)
	clock.onSleep = nil
	if !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), "gateway busy") {
		t.Fatalf("a list that fails during the wait: %v", err)
	}

	c, f = computeGateway(t, openshell.DriverDocker, map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted, "dc-x": openshell.PhaseStarting}, nil)
	before = clock.waited()
	if err := openshell.FlushSandboxes(context.Background(), c); err != nil || clock.waited() != before || len(execsIn(f)) != 0 {
		t.Fatalf("docker: %v, waited %s, ran in %v", err, clock.waited()-before, execsIn(f))
	}
}

// RestartHolds is the restart's gate as the consent questions read it.
func TestRestartHolds(t *testing.T) {
	c, _ := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{
		"ready": openshell.PhaseReady, "starting": openshell.PhaseStarting, "done": openshell.PhaseCompleted, "failed": openshell.PhaseError,
		"unpolled": openshell.PhaseError, "timedout": openshell.PhaseError, "off": openshell.PhaseStopped,
	}, map[string]v1.SandboxCondition{"failed": failedMain, "unpolled": unpolled, "timedout": timedOut})
	list, err := c.ListSandboxes(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2][2]bool{
		// {MicroVM driver: holds, ended}, {docker: holds, ended}
		"ready": {{true, false}, {true, false}}, "starting": {{true, false}, {true, false}},
		"done": {{true, true}, {false, false}}, "failed": {{true, true}, {false, false}},
		"unpolled": {{true, false}, {false, false}}, "timedout": {{false, false}, {false, false}},
		"off": {{false, false}, {false, false}},
	}
	for _, sb := range list {
		for i, stopFlushes := range []bool{false, true} {
			holds, isEnded := openshell.RestartHolds(sb, stopFlushes)
			if w := want[sb.Name][i]; holds != w[0] || isEnded != w[1] {
				t.Errorf("RestartHolds(%s, stopFlushes %v) = %v, %v; want %v", sb.Name, stopFlushes, holds, isEnded, w)
			}
		}
	}
}
