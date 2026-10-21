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
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// TestAHostLeftOnAnOlderOpenShellUpgradesInPlace: DefenseClaw 1.0.0 to
// 1.0.3 left hosts on OpenShell 0.1.1 to 0.1.3, whose network broker can let
// a sandbox's connections bypass its policy (NVIDIA/OpenShell#4494). The
// daemon still connects to such a gateway and drives the sandboxes there
// (status, stop), so their work is kept, but creates and starts none,
// naming the in-place upgrade. A sandbox whose session runs that release's
// supervisor is named until it stops and starts on the upgraded gateway.
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
	if got := e.boxOf("kept").rec.SessionRelease; got != openshell.SandboxMin {
		t.Fatalf("session release = %q, want %s", got, openshell.SandboxMin)
	}
	oldSupervisor := func() []sandboxapi.ActivityEvent {
		return e.events("kept", sandboxapi.ActivityFinding, sandboxapi.ReasonOldSupervisor)
	}
	if n := len(oldSupervisor()); n != 0 || slices.Contains(e.get("kept").Warnings, oldSupervisorWarning) {
		t.Fatalf("a session on %s is named: %d findings, warnings %v", openshell.SandboxMin, n, e.get("kept").Warnings)
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
	// A session that starts on it (outside DefenseClaw) runs its supervisor.
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseProvisioning})
	e.m.statusEvent(t.Context(), e.boxOf("kept"), &stream.Status{Phase: openshell.PhaseReady})
	found := oldSupervisor()
	if len(found) != 1 || found[0].Severity != "HIGH" || !strings.Contains(found[0].Message, "kept's session started on OpenShell 0.1.3") ||
		!strings.Contains(found[0].Message, "stop it (`defenseclaw sandbox stop kept`), upgrade OpenShell 0.1.3 to "+openshell.InstallerVersion) {
		t.Fatalf("old-supervisor findings = %+v", found)
	}
	if !slices.Contains(e.get("kept").Warnings, oldSupervisorWarning) {
		t.Fatalf("warnings = %v", e.get("kept").Warnings)
	}
	// Its work is kept: the old gateway still stops it, but starts it no more.
	e.stopBox("kept")
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
	if !strings.Contains(msg, "box's session started before DefenseClaw kept the OpenShell release a session starts on, so it may run a supervisor older than "+openshell.SandboxMin) ||
		!strings.HasSuffix(msg, "`defenseclaw sandbox stop box` and `defenseclaw sandbox start box` restart it on this gateway's supervisor") {
		t.Fatalf("message = %q", msg)
	}
	e := newEnv(t, nil)
	if got := e.m.upgradeWayOn(openshell.SandboxMin); got != "" {
		t.Fatalf("upgrade way on %s = %q", openshell.SandboxMin, got)
	}
	if got := e.m.upgradeWayOn("dev"); got != "" {
		t.Fatalf("upgrade way on an unreadable release = %q", got)
	}
}
