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
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// TestMayHoldCompute: a gateway stop waits for every phase but stopped and
// deleting, an unknown one and one this build does not name included; a
// sandbox whose workload ended (completed, error) holds nothing only where
// the driver's stop flushes (docker), since a MicroVM keeps running after
// its workload ends (GAP-0012).
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
	for p, ended := range map[openshell.SandboxPhase]bool{openshell.PhaseCompleted: true, openshell.PhaseError: true,
		openshell.PhaseReady: false, openshell.PhaseStopped: false, openshell.PhaseUnknown: false} {
		if openshell.WorkloadEnded(p) != ended {
			t.Errorf("WorkloadEnded(%q) = %v", p, !ended)
		}
	}
}

// TestPrepareUpgradeWaitsForEveryMicroVMThatMayHoldCompute: on the MicroVM
// driver the upgrade's gateway restart stops every sandbox, so a MicroVM
// starting, stopping or in a phase OpenShell does not name refuses it as a
// ready one does; one whose workload ended (completed, or the error state
// that an OpenShell before 0.1.5 cannot stop) still runs, and has its disk
// flushed now: it refuses the upgrade only when the flush fails, and the
// refusal says how to flush it. One whose provisioning timed out ran
// nothing, and is not flushed. On docker none of this applies.
func TestPrepareUpgradeWaitsForEveryMicroVMThatMayHoldCompute(t *testing.T) {
	gateway := func(t *testing.T, d openshell.ComputeDriver, phases map[string]openshell.SandboxPhase) (openshell.Client, *openshelltest.Fake) {
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
		}
		return c, f
	}
	synced := func(f *openshelltest.Fake) []string {
		var out []string
		for _, c := range f.ExecCalls() {
			if strings.Join(c.Command, " ") == "/bin/sync" {
				out = append(out, c.Sandbox)
			}
		}
		slices.Sort(out)
		return out
	}
	pull := func(context.Context) error { return nil }

	for _, phase := range []openshell.SandboxPhase{openshell.PhaseStarting, openshell.PhaseStopping, openshell.PhaseUnknown, "Hibernating"} {
		c, _ := gateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-x": phase, "dc-off": openshell.PhaseStopped})
		err := openshell.PrepareUpgrade(context.Background(), c, pull)
		if !errors.Is(err, openshell.ErrSandboxesRunning) || !strings.Contains(err.Error(), "(dc-x): stop them first with `defenseclaw sandbox stop NAME`") {
			t.Errorf("a MicroVM in phase %q: %v", phase, err)
		}
	}

	ended := map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted, "dc-failed": openshell.PhaseError, "dc-off": openshell.PhaseStopped}
	c, f := gateway(t, openshell.DriverVM, ended)
	if err := openshell.PrepareUpgrade(context.Background(), c, pull); err != nil {
		t.Fatalf("ended MicroVMs that were flushed: %v", err)
	}
	if got := synced(f); !slices.Equal(got, []string{"dc-done", "dc-failed"}) {
		t.Fatalf("flushed %v, want the ended ones", got)
	}

	c, f = gateway(t, openshell.DriverVM, ended)
	f.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if call.Sandbox == "dc-failed" {
			return openshelltest.ExecResponse{Err: errors.New("exec relay closed")}
		}
		return openshelltest.ExecResponse{}
	})
	err := openshell.PrepareUpgrade(context.Background(), c, pull)
	if !errors.Is(err, openshell.ErrSandboxesRunning) ||
		!strings.Contains(err.Error(), ": DefenseClaw could not flush the disks of the MicroVMs whose workload ended (dc-failed, error: ") ||
		!strings.Contains(err.Error(), "`defenseclaw sandbox stop NAME` flushes and stops one, and flushes one in OpenShell's error state that this OpenShell cannot stop, then upgrade") ||
		strings.Contains(err.Error(), "dc-done") {
		t.Fatalf("an ended MicroVM that could not be flushed: %v", err)
	}

	// Both kinds at once are both named.
	c, f = gateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-up": openshell.PhaseReady, "dc-done": openshell.PhaseCompleted})
	f.HandleExec(func(context.Context, openshelltest.ExecCall) openshelltest.ExecResponse {
		return openshelltest.ExecResponse{ExitCode: 1}
	})
	err = openshell.PrepareUpgrade(context.Background(), c, pull)
	if !errors.Is(err, openshell.ErrSandboxesRunning) || !strings.Contains(err.Error(), "(dc-up): stop them first") ||
		!strings.Contains(err.Error(), "; DefenseClaw could not flush the disks of the MicroVMs whose workload ended (dc-done, completed: sync(1) exited with status 1)") {
		t.Fatalf("a running and an unflushed MicroVM: %v", err)
	}

	// Provisioning that timed out: nothing ran in it since its last stop.
	c, f = gateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-timeout": openshell.PhaseError})
	sb, err := f.Sandboxes().Get(context.Background(), openshell.DefaultWorkspace, "dc-timeout")
	if err != nil {
		t.Fatal(err)
	}
	sb.Status.Conditions = []v1.SandboxCondition{{Type: "Ready", Status: "False", Reason: "ProvisioningTimedOut", Message: "Provisioning repair window expired after 300 seconds"}}
	sb.ResourceVersion++
	f.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
	if err := openshell.PrepareUpgrade(context.Background(), c, pull); err != nil || len(synced(f)) != 0 {
		t.Fatalf("a MicroVM whose provisioning timed out: %v, flushed %v", err, synced(f))
	}

	// Docker keeps its sandboxes through the restart.
	pulls := 0
	c, f = gateway(t, openshell.DriverDocker, map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted, "dc-x": openshell.PhaseStarting})
	if err := openshell.PrepareUpgrade(context.Background(), c, func(context.Context) error { pulls++; return nil }); err != nil || pulls != 1 || len(synced(f)) != 0 {
		t.Fatalf("docker: %v, pulled %d, flushed %v", err, pulls, synced(f))
	}
}
