// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strings"
	"testing"
)

// Review P1 (GAP-0352, 1.0.4 loop round 5): a hook guardian that cannot
// resolve the standalone layout (on Windows, a failed lookup of the
// protected ProgramData registration) finds the protected session record
// folder from the data directory it runs with, so it can still hold the
// records and bump their generation; a data directory of another shape
// names none.
func TestStandaloneHookSessionDirForDataDir(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		layout, err := StandaloneLayoutFor(goos)
		if err != nil {
			t.Fatal(err)
		}
		for _, dataDir := range []string{layout.DataDir, layout.DataDir + "/", " " + layout.DataDir} {
			if got, ok := StandaloneHookSessionDirForDataDir(goos, dataDir); !ok || got != layout.HookSessionDir {
				t.Fatalf("%s %q: %q %v, want %q", goos, dataDir, got, ok, layout.HookSessionDir)
			}
		}
		for _, dataDir := range []string{"", "/tmp/data", layout.DataDir + "/x", "relative"} {
			if got, ok := StandaloneHookSessionDirForDataDir(goos, dataDir); ok {
				t.Fatalf("%s %q must name no record folder: %q", goos, dataDir, got)
			}
		}
	}
	for _, programData := range []string{`C:\ProgramData`, `D:\Data`} {
		layout, err := StandaloneWindowsLayoutForRoots(`C:\Program Files`, programData)
		if err != nil {
			t.Fatal(err)
		}
		for _, dataDir := range []string{layout.DataDir, layout.DataDir + `\`, strings.ToLower(layout.DataDir)} {
			got, ok := StandaloneHookSessionDirForDataDir("windows", dataDir)
			if !ok || !strings.EqualFold(got, layout.HookSessionDir) {
				t.Fatalf("windows %q: %q %v, want %q", dataDir, got, ok, layout.HookSessionDir)
			}
		}
	}
	for _, dataDir := range []string{"", `C:\Users\u\.defenseclaw`, `\Cisco\DefenseClaw\runtime`, `relative\Cisco\DefenseClaw\runtime`, `C:\ProgramData\Cisco\DefenseClaw\runtime\x`} {
		if got, ok := StandaloneHookSessionDirForDataDir("windows", dataDir); ok {
			t.Fatalf("windows %q must name no record folder: %q", dataDir, got)
		}
	}
}

// The holds of the record folder are named after it, and on Windows they
// are in the hook runtime folder next to it (enterprisepolicy
// PublishedSessionHoldDir), which the layout names with the same constant.
func TestHookSessionHoldNames(t *testing.T) {
	layout, err := StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	if got := HookSessionHoldPrefix(layout.HookSessionDir); got != StandaloneWindowsHookSessionDirName+".hold" {
		t.Fatalf("Windows hold prefix %q", got)
	}
	if !strings.EqualFold(layout.HookRuntimeDir, windowsParent(layout.HookSessionDir)+`\`+StandaloneWindowsHookRuntimeDirName) {
		t.Fatalf("the hook runtime folder %q must be next to the record folder %q", layout.HookRuntimeDir, layout.HookSessionDir)
	}
	unix, err := StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	if got := HookSessionHoldPrefix(unix.HookSessionDir); got != "sessions.hold" {
		t.Fatalf("Linux hold prefix %q", got)
	}
	if got := HookSessionHoldPrefix(unix.HookSessionDir + "/"); got != "sessions.hold" {
		t.Fatalf("a trailing slash changes nothing: %q", got)
	}
}
