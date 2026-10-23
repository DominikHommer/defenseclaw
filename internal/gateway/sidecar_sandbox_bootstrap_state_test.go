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

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stageLegacyBootstrap puts OpenShell 0.1.3's bootstrap files of the Docker
// sandbox id under stateHome, as its docker driver wrote them.
func stageLegacyBootstrap(t *testing.T, stateHome, id string) string {
	t.Helper()
	dir := filepath.Join(stateHome, "openshell", "docker-sandbox-tokens", "defenseclaw-managed", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"boundary-bootstrap.json", "runtime-descriptor.json"} {
		data, err := os.ReadFile(filepath.Join("..", "openshell", "testdata", "docker-bootstrap", "0.1.3", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func bootstrapMoved(t *testing.T, dir string) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "runtime-descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	return !strings.Contains(string(data), "outer_fence")
}

// TestTheBootstrapMigrationLooksWhereTheGatewayKeepsItsState: a managed
// daemon whose own environment has XDG_STATE_HOME (a session or user
// manager that sets it) scanned that folder, but the exec shim starts the
// account's OpenShell gateway with HOME and no XDG_STATE_HOME, so the
// gateway keeps its Docker sandboxes in ~/.local/state: the migration found
// nothing there, and a sandbox made before OpenShell 0.1.5 could not start
// on 0.1.5. It moves the gateway's files now, and leaves the daemon's
// folder alone. The per-user gateway's OpenShell, which the person started
// with or without XDG_STATE_HOME, is looked for in both.
func TestTheBootstrapMigrationLooksWhereTheGatewayKeepsItsState(t *testing.T) {
	const id = "173db0f1-f401-4104-b94b-aaec75789fc3"
	home, xdg := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", xdg)
	restore := sandboxAccountHomeDir
	t.Cleanup(func() { sandboxAccountHomeDir = restore })
	sandboxAccountHomeDir = func() string { return home }

	gatewayDir := stageLegacyBootstrap(t, filepath.Join(home, ".local", "state"), id)
	daemonDir := stageLegacyBootstrap(t, xdg, id)
	moved, err := dockerBootstrapMigrator(true)(id)
	if err != nil || len(moved) != 2 || !bootstrapMoved(t, gatewayDir) {
		t.Fatalf("managed: moved %v, %v", moved, err)
	}
	if bootstrapMoved(t, daemonDir) {
		t.Fatal("managed: the daemon's own XDG_STATE_HOME, which its gateway never reads, was rewritten")
	}

	// The per-user gateway: wherever the person's OpenShell kept them.
	for _, stateHome := range []string{xdg, filepath.Join(home, ".local", "state")} {
		if err := os.RemoveAll(filepath.Join(home, ".local")); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(xdg, "openshell")); err != nil {
			t.Fatal(err)
		}
		dir := stageLegacyBootstrap(t, stateHome, id)
		moved, err := dockerBootstrapMigrator(false)(id)
		if err != nil || len(moved) != 2 || !bootstrapMoved(t, dir) {
			t.Fatalf("per-user, state in %s: moved %v, %v", stateHome, moved, err)
		}
	}

	// A managed account with no home is an error, not a silent no-op.
	sandboxAccountHomeDir = func() string { return "" }
	if _, err := dockerBootstrapMigrator(true)(id); err == nil {
		t.Fatal("a managed account with no home migrated nothing and said nothing")
	}
}
