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

package sandboxcli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestDoctorAdviceForAnOldErrorStateMicroVM: on an OpenShell before 0.1.5
// a MicroVM in the error state can be neither stopped nor started, and
// nothing flushes it. The round before said the upgrade (or, on a managed
// computer, the administrator's pin move) waits two minutes for its guest
// to write its disk back, which keeps its work; but what its workload
// left running may still write then. The advice now matches what the
// upgrade does: it waits for the MicroVM until its user lets it go
// (`defenseclaw sandbox stop`, which loses what is not on its disk yet)
// or deletes it, whatever OpenShell says of why, but for a VM that is
// gone, which runs nothing, and one its user let go already. A docker
// sandbox keeps the plain advice.
func TestDoctorAdviceForAnOldErrorStateMicroVM(t *testing.T) {
	check := func(ta *testApp) openshell.Check {
		t.Helper()
		ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport { return &openshell.DoctorReport{} }
		for _, c := range ta.runDoctor(bg).Checks {
			if c.ID == CheckIDHooks {
				return c
			}
		}
		t.Fatal("no sandbox-hooks check")
		return openshell.Check{}
	}
	after := ", then `defenseclaw sandbox stop NAME` and `defenseclaw sandbox start NAME` for hic, which keep the sandbox and its work"
	held := func(move string) string {
		return move + " waits for hic, whose MicroVM may still run what its workload left running, which nothing in OpenShell flushes or stops: " +
			"`defenseclaw sandbox stop NAME` lets " + move + " stop it with the gateway (what is not on its disk by then is lost), and `defenseclaw sandbox delete NAME` deletes it"
	}
	perUser := "upgrade OpenShell to " + openshell.InstallerVersion
	managed := "your organization's OpenShell setting moves this account to " + openshell.InstallerVersion + " on its own where DefenseClaw installs OpenShell (ask IT otherwise)"
	for _, tc := range []struct {
		name, driver, reason, asked string
		managed                     bool
		want                        string
	}{
		{"per user", "vm", "MainProcessFailed: Canonical main process exited with status 1", "", false,
			perUser + " (see Gateway; " + held("the upgrade") + ")" + after},
		{"per user, let go", "vm", "MainProcessFailed: Canonical main process exited with status 1", "error", false,
			perUser + " (see Gateway)" + after},
		{"managed", "vm", "MainProcessFailed: Canonical main process exited with status 1", "", true,
			managed + " (" + held("the move") + ")" + after},
		{"managed, not polled", "vm", "ProcessPollFailed: Bad file descriptor", "", true,
			managed + " (" + held("the move") + ")" + after},
		{"managed, VM gone", "vm", "ProcessExited: VM process exited with status 1", "", true, managed + after},
		{"docker", "docker", "ContainerExited: exited", "", false, perUser + " (see Gateway)" + after},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Gateway.Version = "0.1.3"
			if tc.managed {
				ta.daemon.status.Managed = &sandboxapi.ManagedStatus{}
			}
			lost := sampleSandbox("hic")
			lost.Phase, lost.Driver, lost.PhaseReason, lost.StopAskedIn = "error", tc.driver, tc.reason, tc.asked
			ta.daemon.add(lost)
			c := check(ta)
			if c.Status != openshell.StatusWarn || c.Fix == nil || c.Fix.Summary != tc.want {
				t.Fatalf("advice = %+v\nwant %q", c, tc.want)
			}
			if strings.Contains(c.Fix.Summary, "disk back") || strings.Contains(c.Fix.Summary, "stop NAME` flushes") {
				t.Fatalf("the advice still counts on a flush nothing makes: %q", c.Fix.Summary)
			}
		})
	}
}

// endedOn has a MicroVM gateway of release (the fake's own when empty)
// with the sandbox dc-done, whose workload completed, and running ready
// ones.
func endedOn(t *testing.T, ta *testApp, release string, running int) {
	t.Helper()
	fake, client := useGateway(ta)
	fake.SetDriver(openshell.DriverVM)
	if release != "" {
		fake.SetRelease(release)
	}
	phases := map[string]openshell.SandboxPhase{"dc-done": openshell.PhaseCompleted}
	for i := range running {
		phases["dc-claude-theirs-"+string(rune('a'+i))] = openshell.PhaseReady
	}
	for name, phase := range phases {
		if _, err := client.CreateSandbox(bg, name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := fake.SetPhase(openshell.DefaultWorkspace, name, phase); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRestartConsentHoldsForLingeringMicroVMs: the consent questions of
// the gateway restarts DefenseClaw makes (doctor --fix, setup) read the
// sandboxes as the restart's own gate does (openshell.QuiesceSandboxes).
// The round before told the user that the restart waits up to two minutes
// for a MicroVM whose workload ended and then keeps its work, and applied
// the fix with --yes. Now such a MicroVM refuses the restart until its
// user lets it go: the question says so and defaults to no, --yes does not
// fix it, and once the daemon reports it let go (StopAskedIn) the fix
// applies. Running sandboxes are stopped first with OpenShell's own
// flushing stop, which an OpenShell before 0.1.5 does not have: there the
// restart is refused while they run.
func TestRestartConsentHoldsForLingeringMicroVMs(t *testing.T) {
	applied := 0
	report := hostReport(func(r *openshell.DoctorReport) {
		r.Driver = openshell.DriverVM
		r.Checks = append(r.Checks, openshell.Check{ID: openshell.CheckIDVMResources, Title: "MicroVM resources", Status: openshell.StatusWarn,
			Detail: "every MicroVM gets 2 vCPUs", Fix: &openshell.Fix{Summary: "raise them and restart the gateway", Automatic: true, RestartsGateway: true,
				Apply: func(context.Context) error { applied++; return nil }}})
	})
	const held = "MicroVM resources: this restarts the OpenShell gateway: it is refused while the 1 MicroVM whose workload ended (dc-done) may still run " +
		"what its workload left running, which nothing in OpenShell flushes or stops: `defenseclaw sandbox stop NAME` lets the restart stop it " +
		"(what is not on its disk by then is lost), and `defenseclaw sandbox delete NAME` deletes it"

	ta := newTestApp(t, "")
	ta.HostDoctor = report
	endedOn(t, ta, openshell.SandboxMin, 0)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	has(t, ta.output(), held, "not fixed with --yes while a MicroVM whose workload ended holds the gateway")
	lacks(t, ta.output(), "disk back", "work kept")
	if applied != 0 {
		t.Fatalf("a lingering MicroVM: applied %d times", applied)
	}

	// Let go: the fix applies.
	ta = newTestApp(t, "")
	ta.HostDoctor = report
	endedOn(t, ta, openshell.SandboxMin, 0)
	done := sampleSandbox("dc-done")
	done.Phase, done.Driver, done.StopAskedIn = "completed", "vm", "completed"
	ta.daemon.add(done)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	lacks(t, ta.output(), "it is refused while", "not fixed with --yes")
	if applied != 1 {
		t.Fatalf("a MicroVM its user let go: applied %d times", applied)
	}

	// Running ones too: stopped with OpenShell's flushing stop on 0.1.5,
	// refused on an older OpenShell.
	ta = newTestApp(t, "")
	ta.HostDoctor = report
	endedOn(t, ta, openshell.SandboxMin, 1)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	has(t, ta.output(), held, "which stops the 1 sandbox running on it (dc-claude-theirs-a), each first with OpenShell's own stop, which flushes its disk")
	ta = newTestApp(t, "")
	ta.HostDoctor = report
	endedOn(t, ta, "0.1.3", 1)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	has(t, ta.output(), "which this OpenShell refuses while sandboxes run on it (dc-claude-theirs-a): it stops a MicroVM without flushing its disk")
	if applied != 1 {
		t.Fatalf("running sandboxes with --yes: applied %d times", applied)
	}

	// setup's restart: no by default.
	ta = newTestApp(t, "")
	endedOn(t, ta, openshell.SandboxMin, 0)
	ok, err := ta.consentGatewayRestart(bg, SetupOptions{}, true, true, false)
	if err != nil || ok {
		t.Fatalf("setup with a lingering MicroVM: %v, %v", ok, err)
	}
	has(t, ta.output(), "applying this restarts the OpenShell gateway: its running MicroVM sandboxes stop first, with OpenShell's own stop, which flushes their disks, "+
		"and no sandbox runs on it; it is refused while the 1 MicroVM whose workload ended (dc-done)")
}
