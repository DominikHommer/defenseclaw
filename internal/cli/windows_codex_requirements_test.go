// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func TestValidateWindowsStagedRetireGatewayLayout(t *testing.T) {
	const programData = `C:\ProgramData`
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileStandalone, `C:\Program Files`, programData)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(programData, "DefenseClaw-Enterprise-Setup-"+strings.Repeat("a", 32), "defenseclaw-gateway.exe")
	metadata := windowsCodexDeploymentMetadata{
		SchemaVersion:  1,
		DeploymentMode: "managed_enterprise",
		InstallRoot:    roots.InstallRoot,
		StateRoot:      roots.StateRoot,
	}
	cases := []struct {
		name       string
		executable string
		stateRoot  string
		mutate     func(*windowsCodexDeploymentMetadata)
		wantError  string
	}{
		{name: "verified Setup gateway", executable: stage, stateRoot: roots.StateRoot},
		{name: "installed gateway", executable: filepath.Join(roots.InstallRoot, "bin", "defenseclaw-gateway.exe"), stateRoot: roots.StateRoot, wantError: "exact protected Setup gateway path"},
		{name: "foreign staging root", executable: filepath.Join(programData, "other", "defenseclaw-gateway.exe"), stateRoot: roots.StateRoot, wantError: "exact protected Setup gateway path"},
		{name: "wrong executable", executable: filepath.Join(filepath.Dir(stage), "defenseclaw-hook.exe"), stateRoot: roots.StateRoot, wantError: "exact protected Setup gateway path"},
		{name: "short Setup ID", executable: filepath.Join(programData, "DefenseClaw-Enterprise-Setup-aa", "defenseclaw-gateway.exe"), stateRoot: roots.StateRoot, wantError: "exact protected Setup gateway path"},
		{name: "nonhex Setup ID", executable: filepath.Join(programData, "DefenseClaw-Enterprise-Setup-"+strings.Repeat("g", 32), "defenseclaw-gateway.exe"), stateRoot: roots.StateRoot, wantError: "exact protected Setup gateway path"},
		{name: "wrong state root", executable: stage, stateRoot: filepath.Join(programData, "other"), wantError: "matching installed deployment metadata"},
		{name: "wrong schema", executable: stage, stateRoot: roots.StateRoot, mutate: func(m *windowsCodexDeploymentMetadata) { m.SchemaVersion = 2 }, wantError: "matching installed deployment metadata"},
		{name: "wrong mode", executable: stage, stateRoot: roots.StateRoot, mutate: func(m *windowsCodexDeploymentMetadata) { m.DeploymentMode = "personal" }, wantError: "matching installed deployment metadata"},
		{name: "inactive install", executable: stage, stateRoot: roots.StateRoot, mutate: func(m *windowsCodexDeploymentMetadata) { inactive := false; m.Installed = &inactive }, wantError: "matching installed deployment metadata"},
		{name: "foreign install root", executable: stage, stateRoot: roots.StateRoot, mutate: func(m *windowsCodexDeploymentMetadata) { m.InstallRoot = filepath.Join(programData, "other") }, wantError: "install root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := metadata
			if tc.mutate != nil {
				tc.mutate(&current)
			}
			got, err := validateWindowsStagedRetireGatewayLayout(tc.executable, tc.stateRoot, programData, current, roots)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("layout error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil || !sameWindowsEnterprisePathCLI(got, roots.InstallRoot) {
				t.Fatalf("layout root = %q, err=%v, want %q", got, err, roots.InstallRoot)
			}
		})
	}
}

func TestTrimWindowsJSONBOMAcceptsLegacyPowerShell51Output(t *testing.T) {
	plain := []byte(`{"schema_version":1}`)
	legacy := append([]byte{0xef, 0xbb, 0xbf}, plain...)
	if got := trimWindowsJSONBOM(legacy); !bytes.Equal(got, plain) {
		t.Fatalf("trim legacy BOM = %x, want %x", got, plain)
	}
	if got := trimWindowsJSONBOM(plain); !bytes.Equal(got, plain) {
		t.Fatalf("BOM-less JSON changed: %x", got)
	}
}

func TestEnableWindowsCodexManifestTargetsUsesGuardianManifest(t *testing.T) {
	stateRoot := filepath.Clean(`C:\ProgramData\DefenseClaw\state`)
	want := filepath.Join(stateRoot, "hook-guardian", "targets.yaml")
	oldTrust := windowsCodexRequirementsManifestTrust
	oldLoader := windowsCodexRequirementsManifestLoader
	t.Cleanup(func() {
		windowsCodexRequirementsManifestTrust = oldTrust
		windowsCodexRequirementsManifestLoader = oldLoader
	})
	var trustedPath, loadedPath string
	windowsCodexRequirementsManifestTrust = func(path, _ string) error {
		trustedPath = path
		return nil
	}
	windowsCodexRequirementsManifestLoader = func(path string) (enterprisehooks.Manifest, error) {
		loadedPath = path
		return enterprisehooks.Manifest{
			Version: 1,
			Targets: []enterprisehooks.ManifestTarget{
				{Connector: "claudecode"},
				{Connector: "codex"},
				{Connector: "cursor"},
			},
		}, nil
	}

	var opts connector.WindowsCodexMachineRequirementsOptions
	if err := enableWindowsCodexManifestTargets(stateRoot, &opts); err != nil {
		t.Fatal(err)
	}
	if trustedPath != want || loadedPath != want {
		t.Fatalf("manifest trust/load paths = %q / %q, want exact %q", trustedPath, loadedPath, want)
	}
	if trustedPath == filepath.Join(stateRoot, "etc", "targets.yaml") {
		t.Fatal("legacy etc targets path must never be consulted")
	}
	if !opts.CodexTargetEnabled || !opts.ClaudeTargetEnabled || !opts.CursorTargetEnabled {
		t.Fatalf("manifest targets = %+v, want all three enabled", opts)
	}
}
