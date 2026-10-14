// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// packagedDockerHost is a Linux host with the administrator's OpenShell and
// docker installed.
func packagedDockerHost(t *testing.T) *osHost {
	t.Helper()
	h := newOSHost(t, "linux")
	for _, p := range []string{"/usr/bin/openshell", "/usr/bin/openshell-gateway", "/usr/bin/docker", "/usr/sbin/mke2fs"} {
		if err := os.MkdirAll(filepath.Dir(h.env.P(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.env.P(p), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.runner.replies = map[string]fakeReply{"rpm -q --qf %{VERSION} openshell": {result: CommandResult{Stdout: []byte("0.1.3")}}}
	return h
}

// GAP-0587: 1.0.1 rendered the managed docker gateway without a
// sandbox_label, so the sandboxes its accounts kept are in OpenShell's
// default namespace. The upgraded render names the managed namespace, and a
// gateway lists only its own namespace's sandboxes: the change strands them
// as a driver switch does. It was counted a plain restart, which said
// nothing. It is a switch now: it waits while the account runs a sandbox,
// then says what happens to the sandboxes made before (the GAP-0663
// guidance) and where their Docker objects stay; an account that never used
// sandboxes is left alone.
func TestUpgradeToTheManagedDockerNamespaceIsASwitch(t *testing.T) {
	h := packagedDockerHost(t)
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, GID: h.alice.GID, Home: "/home/bob"}
	if err := os.MkdirAll(h.env.P(bob.Home), 0o755); err != nil {
		t.Fatal(err)
	}
	h.ops.accounts = append(h.ops.accounts, bob)
	cfg := sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "gateway_port": 17671})
	ensureWith := func(payload string) *enterprisestatus.Result {
		t.Helper()
		return h.run(Options{Action: ActionEnsure, PayloadDir: payload, ConfigFile: writeTempConfig(t, cfg)})
	}
	requireOK(t, h.ensure(cfg))

	// The record as 1.0.1 left it: no docker namespace, and the daemon
	// inputs of its render.
	state := h.env.loadOpenShellState()
	if state.Applied == nil || state.Applied.DockerNamespace != openshell.ManagedDockerNamespace {
		t.Fatalf("applied record = %+v, want docker_namespace %q", state.Applied, openshell.ManagedDockerNamespace)
	}
	state.Applied.DockerNamespace = ""
	state.Applied.DaemonInputs = "sha256:inputs-of-a-render-without-sandbox_label"
	if err := h.env.saveOpenShellState(state); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(h.env.openshellStatePath()); err != nil || strings.Contains(string(raw), "docker_namespace") {
		t.Fatalf("the 1.0.1 record names a namespace: %s %v", raw, err)
	}
	// alice kept sandboxes and runs one now; bob never used sandboxes.
	if err := os.MkdirAll(h.env.P(filepath.Join(h.alice.Home, h.env.daemonStateRel())), 0o700); err != nil {
		t.Fatal(err)
	}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}

	upgraded := h.payload("1.0.2")
	r := ensureWith(upgraded)
	requireOK(t, r)
	const reason = "docker sandbox namespace " + openshell.DefaultDockerNamespace + " -> " + openshell.ManagedDockerNamespace
	entry, waiting := h.env.loadOpenShellState().Pending[strconv.Itoa(h.alice.UID)]
	if !waiting || entry.Kind != "switch" || entry.reasonBase() != reason {
		t.Fatalf("alice's pending change = %+v (waiting %t), want a switch for %q", entry, waiting, reason)
	}
	if !hasWarning(r, codeSandboxPending) || len(h.ops.stopped()) != 0 {
		t.Fatalf("a running sandbox was not waited for: stops %v, warnings %+v", h.ops.stopped(), r.Warnings)
	}

	// The sandbox ends: the next run switches the account and says what the
	// switch does to the sandboxes made before.
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	r = ensureWith(upgraded)
	requireOK(t, r)
	changes := strings.Join(r.Changes, "\n")
	if !strings.Contains(changes, "switched the sandbox setup of alice ("+reason+"); "+sandboxSwitchLeftovers) ||
		!strings.Contains(changes, `stay in OpenShell's "default" sandbox namespace`) {
		t.Fatalf("changes = %v", r.Changes)
	}
	if strings.Contains(changes, "of bob") {
		t.Errorf("an account that never used sandboxes was switched: %v", r.Changes)
	}
	if got := strings.Join(h.ops.stopped(), ","); got != "alice:daemon+gateway" {
		t.Errorf("stops = %s", got)
	}
	state = h.env.loadOpenShellState()
	if len(state.Pending) != 0 || state.Applied.DockerNamespace != openshell.ManagedDockerNamespace {
		t.Fatalf("after the switch: pending %+v, applied %+v", state.Pending, state.Applied)
	}

	// The next upgrade keeps the namespace: no switch.
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
	requireOK(t, ensureWith(h.payload("1.0.3")))
	if entry, waiting := h.env.loadOpenShellState().Pending[strconv.Itoa(h.alice.UID)]; waiting && entry.Kind == "switch" {
		t.Fatalf("an upgrade within the managed namespace is a switch: %+v", entry)
	}
}

// A record of a setup without docker gateways (the MicroVM driver without
// the docker fallback) has no namespace to change; one with the docker
// fallback has, and a fallback that goes is the fallback's change only.
func TestDockerNamespaceOfAnAppliedSetup(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    *openshellApplied
		want string
	}{
		{"1.0.1 docker driver", &openshellApplied{Enabled: true, Driver: "docker"}, openshell.DefaultDockerNamespace},
		{"1.0.1 vm with the docker fallback", &openshellApplied{Enabled: true, Driver: "vm", Fallback: "docker"}, openshell.DefaultDockerNamespace},
		{"vm without fallback", &openshellApplied{Enabled: true, Driver: "vm", Fallback: "none"}, ""},
		{"managed docker", &openshellApplied{Enabled: true, Driver: "docker", DockerNamespace: openshell.ManagedDockerNamespace}, openshell.ManagedDockerNamespace},
	} {
		if got := tc.a.dockerNamespace(); got != tc.want {
			t.Errorf("%s: namespace %q, want %q", tc.name, got, tc.want)
		}
	}
	from := &openshellApplied{Enabled: true, Install: "prerequisite", Driver: "vm", Fallback: "none", GatewayPort: 17670}
	to := &openshellApplied{Enabled: true, Install: "prerequisite", Driver: "vm", Fallback: "docker", GatewayPort: 17670, DockerNamespace: openshell.ManagedDockerNamespace}
	if !fallbackOnlySwitch(from, to) || describeSwitch(from, to) != "driver_fallback none -> docker" {
		t.Errorf("a fallback that comes: fallback-only %t, %q", fallbackOnlySwitch(from, to), describeSwitch(from, to))
	}
}
