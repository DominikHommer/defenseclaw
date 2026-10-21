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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
// its workload ends (GAP-0012), with whatever the workload left running.
// Such a MicroVM may linger for any error reason but a VM that is gone and
// a provisioning that timed out: the round before let most error reasons
// go after two minutes, as if nothing ran in them.
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
		phase   openshell.SandboxPhase
		said    string
		lingers bool
		gone    bool
	}{
		{openshell.PhaseCompleted, "", true, false},
		{openshell.PhaseCompleted, "MainProcessCompleted: Canonical main process exited", true, false},
		{openshell.PhaseError, "", true, false},
		{openshell.PhaseError, "MainProcessFailed: Canonical main process exited with status 1", true, false},
		{openshell.PhaseError, "ProcessPollFailed: Bad file descriptor", true, false},
		{openshell.PhaseError, "ImagePreparationFailed: no space left on device", true, false},
		{openshell.PhaseError, "MainProcessFailed: the VM process exited with status 1", true, false},
		{openshell.PhaseError, "ProcessExited: VM process exited with status 1", false, true},
		{openshell.PhaseError, "ProcessExited: Canonical main process exited before VM driver restart", false, true},
		{openshell.PhaseError, "MainProcessFailed: exited 1; ProcessExited: host supervisor process exited", false, true},
		{openshell.PhaseError, "ProcessExited", false, true},
		{openshell.PhaseError, "ProvisioningTimedOut: Provisioning repair window expired after 300 seconds", false, false},
		{openshell.PhaseReady, "", false, false},
		{openshell.PhaseStopped, "", false, false},
		{openshell.PhaseUnknown, "", false, false},
	} {
		if got := openshell.MayLinger(tc.phase, tc.said); got != tc.lingers {
			t.Errorf("MayLinger(%q, %q) = %v", tc.phase, tc.said, got)
		}
		if got := openshell.VMGone(tc.said); got != tc.gone {
			t.Errorf("VMGone(%q) = %v", tc.said, got)
		}
	}
	sb := &openshell.Sandbox{Name: "dc-done"}
	sb.Status.Phase = openshell.PhaseCompleted
	for _, tc := range []struct {
		asked map[string]string
		want  bool
	}{
		{nil, false},
		{map[string]string{"dc-done": "completed"}, true},
		{map[string]string{"dc-done": "error"}, false},
		{map[string]string{"dc-done": ""}, false},
		{map[string]string{"dc-other": "completed"}, false},
	} {
		if got := openshell.LetGo(tc.asked, sb); got != tc.want {
			t.Errorf("LetGo(%v, completed dc-done) = %v", tc.asked, got)
		}
	}
	if openshell.LetGo(map[string]string{"": ""}, nil) {
		t.Error("LetGo(nil sandbox) = true")
	}
}

// computeGateway is a gateway on driver d with a sandbox in each phase,
// conds giving the conditions of some.
func computeGateway(t *testing.T, d openshell.ComputeDriver, phases map[string]openshell.SandboxPhase, conds map[string]v1.SandboxCondition) (openshell.Client, *openshelltest.Fake) {
	t.Helper()
	f := openshelltest.New(openshelltest.WithDriver(d))
	f.SetRelease(openshell.SandboxMin)
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
	vmGone     = v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "ProcessExited", Message: "VM process exited with status 1"}
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

// lingerVariants are MicroVMs that may linger, whatever time has passed:
// completed, and in the error state with its main process failed, its VM
// not polled, a reason OpenShell gives for something else, or none.
var lingerVariants = []struct {
	name string
	cond *v1.SandboxCondition
}{
	{"completed", nil}, {"failed", &failedMain}, {"unpolled", &unpolled},
	{"imagefail", &v1.SandboxCondition{Type: "Ready", Status: "False", Reason: "ImagePreparationFailed", Message: "no space left on device"}},
	{"noreason", nil},
}

// lingerGateway is a MicroVM gateway with the sandbox dc-x as v, plus a
// stopped one.
func lingerGateway(t *testing.T, v struct {
	name string
	cond *v1.SandboxCondition
}) (openshell.Client, *openshelltest.Fake, openshell.SandboxPhase) {
	t.Helper()
	phase := openshell.PhaseError
	if v.name == "completed" {
		phase = openshell.PhaseCompleted
	}
	conds := map[string]v1.SandboxCondition{}
	if v.cond != nil {
		conds["dc-x"] = *v.cond
	}
	c, f := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": phase, "dc-off": openshell.PhaseStopped}, conds)
	return c, f, phase
}

// TestPrepareUpgradeRefusesEveryMicroVMThatMayHoldCompute: on the MicroVM
// driver the upgrade's gateway restart stops every sandbox, so a MicroVM
// that runs, starts, stops or is in a phase OpenShell does not name
// refuses it. So does one that may linger (completed, or in the error
// state), however long ago its workload ended: the round before let it go
// after two minutes, but what its workload left running may still write,
// and nothing in OpenShell flushes or stops it. Its user lets it go
// (`defenseclaw sandbox stop`, LetGo) for the phase it is in; one that is
// in another phase since is held again. One whose VM is gone, or whose
// provisioning timed out, runs nothing. Nothing is run in any of them. On
// docker none of this applies.
func TestPrepareUpgradeRefusesEveryMicroVMThatMayHoldCompute(t *testing.T) {
	pull := func(context.Context) error { return nil }
	for _, phase := range []openshell.SandboxPhase{
		openshell.PhaseStarting, openshell.PhaseStopping, openshell.PhaseUnknown, "Hibernating", openshell.PhaseProvisioning, openshell.PhaseReady,
	} {
		c, _ := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": phase, "dc-off": openshell.PhaseStopped}, nil)
		err := openshell.PrepareUpgrade(context.Background(), c, pull, map[string]string{"dc-x": strings.ToLower(string(phase))})
		if !errors.Is(err, openshell.ErrSandboxesRunning) || !strings.Contains(err.Error(), "(dc-x: stop them first with `defenseclaw sandbox stop NAME`") {
			t.Errorf("a MicroVM in phase %q: %v", phase, err)
		}
	}
	for _, v := range lingerVariants {
		c, f, phase := lingerGateway(t, v)
		err := openshell.PrepareUpgrade(context.Background(), c, pull, nil)
		if !errors.Is(err, openshell.ErrSandboxesRunning) || !strings.Contains(err.Error(), "(dc-x, "+strings.ToLower(string(phase))+": nothing in OpenShell flushes or stops a MicroVM") ||
			!strings.Contains(err.Error(), "`defenseclaw sandbox stop NAME` lets DefenseClaw stop it with the gateway") {
			t.Errorf("a lingering MicroVM (%s): %v", v.name, err)
		}
		if got := execsIn(f); len(got) != 0 {
			t.Errorf("a lingering MicroVM (%s): ran commands in %v", v.name, got)
		}
		// Let go in its phase: the upgrade goes ahead; in another phase, not.
		if err := openshell.PrepareUpgrade(context.Background(), c, pull, map[string]string{"dc-x": strings.ToLower(string(phase))}); err != nil {
			t.Errorf("a lingering MicroVM (%s) its user let go: %v", v.name, err)
		}
		other := "completed"
		if phase == openshell.PhaseCompleted {
			other = "error"
		}
		if err := openshell.PrepareUpgrade(context.Background(), c, pull, map[string]string{"dc-x": other}); !errors.Is(err, openshell.ErrSandboxesRunning) {
			t.Errorf("a lingering MicroVM (%s) let go in another phase: %v", v.name, err)
		}
	}

	// Its VM gone, or its provisioning timed out: nothing ran in it.
	for _, cond := range []v1.SandboxCondition{vmGone, timedOut} {
		c, f := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": openshell.PhaseError}, map[string]v1.SandboxCondition{"dc-x": cond})
		if err := openshell.PrepareUpgrade(context.Background(), c, pull, nil); err != nil || len(execsIn(f)) != 0 {
			t.Errorf("a MicroVM in the error state (%s): %v, ran in %v", cond.Reason, err, execsIn(f))
		}
	}

	// Docker keeps its sandboxes through the restart.
	pulls := 0
	c, f := computeGateway(t, openshell.DriverDocker, map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted, "dc-x": openshell.PhaseStarting}, nil)
	if err := openshell.PrepareUpgrade(context.Background(), c, func(context.Context) error { pulls++; return nil }, nil); err != nil || pulls != 1 || len(execsIn(f)) != 0 {
		t.Fatalf("docker: %v, pulled %d, ran in %v", err, pulls, execsIn(f))
	}
}

// TestQuiesceSandboxesHoldsForLingeringMicroVMs: a gateway restart that
// DefenseClaw makes (doctor --fix, setup) on the MicroVM driver applies
// the gate the upgrade does. The round before waited two minutes for a
// MicroVM whose workload ended and then restarted under it. Now one that
// may linger refuses the restart, however long it has been so, before
// anything is stopped, unless its user let it go; one let go stays as it
// is (OpenShell cannot stop it) and the ready ones are stopped. One that
// may run work no flush reaches refuses at once. Docker restarts at once.
func TestQuiesceSandboxesHoldsForLingeringMicroVMs(t *testing.T) {
	for _, v := range lingerVariants {
		c, f, phase := lingerGateway(t, v)
		if err := f.SetPhase(openshell.DefaultWorkspace, "dc-off", openshell.PhaseReady); err != nil {
			t.Fatal(err)
		}
		err := openshell.QuiesceSandboxes(context.Background(), c, nil)
		if !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), "(dc-x, "+strings.ToLower(string(phase))+": nothing in OpenShell flushes or stops a MicroVM") {
			t.Errorf("a lingering MicroVM (%s): %v", v.name, err)
		}
		if n := f.Calls(openshelltest.MethodStopSandbox); n != 0 || len(execsIn(f)) != 0 {
			t.Errorf("a lingering MicroVM (%s): %d stops and commands in %v before the refusal", v.name, n, execsIn(f))
		}
		if err := openshell.QuiesceSandboxes(context.Background(), c, map[string]string{"dc-x": strings.ToLower(string(phase))}); err != nil {
			t.Errorf("a lingering MicroVM (%s) its user let go: %v", v.name, err)
		}
		if n := f.Calls(openshelltest.MethodStopSandbox); n != 1 {
			t.Errorf("a lingering MicroVM (%s) let go: %d stops, want the ready one's", v.name, n)
		}
	}

	for _, phase := range []openshell.SandboxPhase{openshell.PhaseStarting, openshell.PhaseStopping, openshell.PhaseProvisioning, openshell.PhaseUnknown} {
		c, f := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": phase, "dc-up": openshell.PhaseReady}, nil)
		err := openshell.QuiesceSandboxes(context.Background(), c, nil)
		if !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), "(dc-x, "+strings.ToLower(string(phase))+": a MicroVM that is starting, stopping") {
			t.Errorf("a MicroVM in phase %q: %v", phase, err)
		}
		if f.Calls(openshelltest.MethodStopSandbox) != 0 || len(execsIn(f)) != 0 {
			t.Errorf("a MicroVM in phase %q: stopped or ran in sandboxes before the refusal", phase)
		}
	}

	for _, cond := range []v1.SandboxCondition{vmGone, timedOut} {
		c, f := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": openshell.PhaseError}, map[string]v1.SandboxCondition{"dc-x": cond})
		if err := openshell.QuiesceSandboxes(context.Background(), c, nil); err != nil || f.Calls(openshelltest.MethodStopSandbox) != 0 {
			t.Errorf("a MicroVM in the error state (%s): %v", cond.Reason, err)
		}
	}

	c, f := computeGateway(t, openshell.DriverDocker, map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted, "dc-x": openshell.PhaseStarting}, nil)
	if err := openshell.QuiesceSandboxes(context.Background(), c, nil); err != nil || f.Calls(openshelltest.MethodStopSandbox) != 0 || len(execsIn(f)) != 0 {
		t.Fatalf("docker: %v", err)
	}
}

// RestartHolds is the restart's gate as the consent questions read it.
func TestRestartHolds(t *testing.T) {
	c, _ := computeGateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{
		"ready": openshell.PhaseReady, "starting": openshell.PhaseStarting, "done": openshell.PhaseCompleted, "failed": openshell.PhaseError,
		"unpolled": openshell.PhaseError, "timedout": openshell.PhaseError, "gone": openshell.PhaseError, "off": openshell.PhaseStopped,
	}, map[string]v1.SandboxCondition{"failed": failedMain, "unpolled": unpolled, "timedout": timedOut, "gone": vmGone})
	list, err := c.ListSandboxes(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2][2]bool{
		// {MicroVM driver: holds, lingers}, {docker: holds, lingers}
		"ready": {{true, false}, {true, false}}, "starting": {{true, false}, {true, false}},
		"done": {{true, true}, {false, false}}, "failed": {{true, true}, {false, false}},
		"unpolled": {{true, true}, {false, false}}, "timedout": {{false, false}, {false, false}},
		"gone": {{false, false}, {false, false}}, "off": {{false, false}, {false, false}},
	}
	for _, sb := range list {
		for i, stopFlushes := range []bool{false, true} {
			holds, lingers := openshell.RestartHolds(sb, stopFlushes)
			if w := want[sb.Name][i]; holds != w[0] || lingers != w[1] {
				t.Errorf("RestartHolds(%s, stopFlushes %v) = %v, %v; want %v", sb.Name, stopFlushes, holds, lingers, w)
			}
		}
	}
}

// TestLifecycleLock: a restart or an upgrade holds the lock exclusively,
// and a create or a start shares it: one is refused at once while the
// other holds it, the exclusive one waits for the shared ones up to its
// bound or its context, and either goes once the other let go. The lock
// file is the owner's only, in a configuration directory the exclusive
// one makes; a start where none exists holds nothing.
func TestLifecycleLock(t *testing.T) {
	skipOnWindows(t)
	openshell.SetLifecycleLockWait(t, 300*time.Millisecond)
	dir := filepath.Join(t.TempDir(), "openshell")
	none, err := openshell.LockSandboxStart(dir)
	if err != nil {
		t.Fatal(err)
	}
	none()
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a start made the configuration directory: %v", err)
	}

	restart, err := openshell.LockGatewayLifecycle(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, ".defenseclaw-lifecycle.lock")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file: %v, %v", info, err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("configuration directory: %v, %v", info, err)
	}
	if _, err := openshell.LockSandboxStart(dir); !errors.Is(err, openshell.ErrGatewayBusy) {
		t.Fatalf("a start during a restart: %v", err)
	}
	if _, err := openshell.LockGatewayLifecycle(context.Background(), dir); !errors.Is(err, openshell.ErrGatewayBusy) {
		t.Fatalf("a second restart: %v", err)
	}
	restart()

	a, err := openshell.LockSandboxStart(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openshell.LockSandboxStart(dir)
	if err != nil {
		t.Fatalf("two starts at once: %v", err)
	}
	if _, err := openshell.LockGatewayLifecycle(context.Background(), dir); !errors.Is(err, openshell.ErrGatewayBusy) {
		t.Fatalf("a restart under starts held past the wait: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := openshell.LockGatewayLifecycle(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("a restart whose context ended: %v", err)
	}
	a()
	go func() { time.Sleep(50 * time.Millisecond); b() }()
	restart, err = openshell.LockGatewayLifecycle(context.Background(), dir)
	if err != nil {
		t.Fatalf("a restart once the starts ended: %v", err)
	}
	restart()
}
