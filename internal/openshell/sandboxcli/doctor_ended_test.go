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
// nothing flushes it. The round before told the user to upgrade first,
// while the upgrade (and, on a managed computer, the administrator's pin
// move, which the user does not run) waited for that very MicroVM to be
// flushed. The advice now matches what the upgrade does per driver and
// mode: it waits until the MicroVM has been in the error state for
// openshell.EndedSettle, which keeps its work, then stop and start; one
// whose VM OpenShell could not poll is waited for until it is deleted. A
// docker sandbox keeps the plain advice.
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
	waits := "waits until hic has been in the error state for " + openshell.EndedSettleWords() +
		": nothing flushes its MicroVM, whose guest writes its disk back by then, which keeps its work"
	for _, tc := range []struct {
		name, driver, reason string
		managed              bool
		want                 string
	}{
		{"per user", "vm", "MainProcessFailed: Canonical main process exited with status 1", false,
			"upgrade OpenShell to " + openshell.InstallerVersion + " (see Gateway; the upgrade " + waits + ")" + after},
		{"managed", "vm", "ProcessExited: VM process exited with status 1", true,
			"your organization's OpenShell setting moves this account to " + openshell.InstallerVersion +
				" on its own where DefenseClaw installs OpenShell (ask IT otherwise) (the move " + waits + ")" + after},
		{"managed, not polled", "vm", "ProcessPollFailed: Bad file descriptor", true,
			"your organization's OpenShell setting moves this account to " + openshell.InstallerVersion +
				" on its own where DefenseClaw installs OpenShell (ask IT otherwise) (the move waits for hic for as long as OpenShell cannot tell whether its MicroVM still runs: " +
				"`defenseclaw sandbox delete NAME` ends that wait if its work is not needed)" + after},
		{"docker", "docker", "ContainerExited: exited", false,
			"upgrade OpenShell to " + openshell.InstallerVersion + " (see Gateway)" + after},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Gateway.Version = "0.1.3"
			if tc.managed {
				ta.daemon.status.Managed = &sandboxapi.ManagedStatus{}
			}
			lost := sampleSandbox("hic")
			lost.Phase, lost.Driver, lost.PhaseReason = "error", tc.driver, tc.reason
			ta.daemon.add(lost)
			c := check(ta)
			if c.Status != openshell.StatusWarn || c.Fix == nil || c.Fix.Summary != tc.want {
				t.Fatalf("advice = %+v\nwant %q", c, tc.want)
			}
			if strings.Contains(c.Fix.Summary, "stop NAME` flushes") {
				t.Fatalf("the advice still counts on a flush OpenShell refuses: %q", c.Fix.Summary)
			}
		})
	}
}

// endedOn has a MicroVM gateway with the sandbox dc-done, whose workload
// completed, and the ready ones of runningOn.
func endedOn(t *testing.T, ta *testApp, running int) {
	t.Helper()
	fake, client := useGateway(ta)
	fake.SetDriver(openshell.DriverVM)
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

// TestRestartConsentNamesTheWaitForEndedMicroVMs: the consent questions of
// the gateway restarts DefenseClaw makes (doctor --fix, setup) read the
// sandboxes as the restart's own gate does (openshell.FlushSandboxes). A
// MicroVM whose workload ended is neither running (the restart loses
// nothing once it has waited for it, so it does not turn the default to
// no) nor left out (before, a restart with no ready sandbox said nothing
// of it): the user is told that the restart waits for it first.
func TestRestartConsentNamesTheWaitForEndedMicroVMs(t *testing.T) {
	applied := 0
	report := hostReport(func(r *openshell.DoctorReport) {
		r.Driver = openshell.DriverVM
		r.Checks = append(r.Checks, openshell.Check{ID: openshell.CheckIDVMResources, Title: "MicroVM resources", Status: openshell.StatusWarn,
			Detail: "every MicroVM gets 2 vCPUs", Fix: &openshell.Fix{Summary: "raise them and restart the gateway", Automatic: true, RestartsGateway: true,
				Apply: func(context.Context) error { applied++; return nil }}})
	})
	const wait = "MicroVM resources: this restarts the OpenShell gateway: it first waits up to 2 minutes for the 1 MicroVM whose workload ended (dc-done) " +
		"to write its disk back, since nothing in OpenShell flushes one, then stops it with its work kept"

	ta := newTestApp(t, "")
	ta.HostDoctor = report
	endedOn(t, ta, 0)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	has(t, ta.output(), wait)
	lacks(t, ta.output(), "not fixed with --yes")
	if applied != 1 {
		t.Fatalf("only an ended MicroVM: applied %d times", applied)
	}

	ta = newTestApp(t, "")
	ta.HostDoctor = report
	endedOn(t, ta, 1)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	has(t, ta.output(), wait, "which stops the 1 sandbox running on it (dc-claude-theirs-a)", "not fixed with --yes")
	if applied != 1 {
		t.Fatalf("an ended MicroVM and a running sandbox: applied %d times", applied)
	}

	// setup's restart.
	ta = newTestApp(t, "")
	endedOn(t, ta, 0)
	ok, err := ta.consentGatewayRestart(bg, SetupOptions{}, true, true, false)
	if err != nil || !ok {
		t.Fatalf("setup with only an ended MicroVM: %v, %v", ok, err)
	}
	has(t, ta.output(), "applying this restarts the OpenShell gateway: it first waits up to 2 minutes for the 1 MicroVM whose workload ended (dc-done)")
}
