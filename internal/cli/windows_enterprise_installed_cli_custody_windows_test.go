// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// GAP-1493: the elevated lifecycle validates the installed CLI's custody
// before it builds a command for it. An image a standard user can replace is
// refused before any process is created.
func TestWindowsEnterpriseInstalledCLICustodyIsCheckedBeforeExec(t *testing.T) {
	newHotConfigHost(t, "config_version: 9\n", "config_version: 9\n")
	var checked string
	windowsEnterpriseInstalledCLICustody = func(path, _ string) error {
		checked = path
		return errors.New("BUILTIN\\Users can write the file")
	}
	command, err := windowsEnterprisePolicyDigestCommand(context.Background())
	if err == nil || command != nil || !strings.Contains(err.Error(), "refuse to run the installed CLI") {
		t.Fatalf("policy digest command = %v, %v; want the custody refusal", command, err)
	}
	if !strings.HasSuffix(strings.ToLower(checked), `\cisco\defenseclaw\bin\defenseclaw.exe`) {
		t.Fatalf("custody checked %q, want the installed CLI", checked)
	}
	windowsEnterpriseInstalledCLICustody = func(string, string) error { return nil }
	if command, err := windowsEnterprisePolicyDigestCommand(context.Background()); err != nil || command == nil {
		t.Fatalf("trusted image: command = %v, %v", command, err)
	}
}
