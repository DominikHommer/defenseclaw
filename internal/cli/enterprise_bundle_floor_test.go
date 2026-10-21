// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

func TestBundleFloorCheckRefusesOnlyBelowTheFloorWithItsOwnExitCode(t *testing.T) {
	root, layout, _ := anchorsInstallDevice(t)
	run := func(args ...string) error {
		t.Helper()
		cmd := newEnterpriseBundleFloorCheckCommand()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd.Execute()
	}
	// No trust anchors: no floor.
	if err := run("--product-version", "0.0.1"); err != nil {
		t.Fatalf("without anchors: %v", err)
	}
	anchors := filepath.Join(root, layout.ConfigDir, "trust", enterprisebundle.AnchorsName)
	if err := os.MkdirAll(filepath.Dir(anchors), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchors, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Anchors but no confirmed bundle: no floor.
	if err := run("--product-version", "0.0.1"); err != nil {
		t.Fatalf("anchors without a bundle: %v", err)
	}
	// The state cannot be read: refused with the floor exit code.
	state := filepath.Join(root, layout.LifecycleDir, enterprisebundle.StateFileName)
	if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run("--product-version", "0.0.1")
	var coded *exitCodeError
	if !errors.As(err, &coded) || coded.ExitCode() != bundleFloorRefusedExit {
		t.Fatalf("unreadable floor = %v; want exit %d", err, bundleFloorRefusedExit)
	}
}
