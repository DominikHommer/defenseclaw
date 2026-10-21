// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// stageWindowsScannerRuntimeTest points the scanner step at a temporary
// root and stages an unsigned scanner executable beside an installer.
func stageWindowsScannerRuntimeTest(t *testing.T) (root, installer, source string) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the scanner runtime root is administrator-only; run elevated")
	}
	dirSeam, accountSeam, sourceSeam, versionSeam := windowsScannerRuntimeDir, windowsScannerGatewayAccount,
		windowsScannerSourceCheck, windowsEnterpriseInstalledProductVersion
	t.Cleanup(func() {
		windowsScannerRuntimeDir, windowsScannerGatewayAccount, windowsScannerSourceCheck = dirSeam, accountSeam, sourceSeam
		windowsEnterpriseInstalledProductVersion = versionSeam
	})
	root = filepath.Join(t.TempDir(), "DefenseClaw-ScannerRuntime")
	windowsScannerRuntimeDir = func() (string, error) { return root, nil }
	windowsScannerGatewayAccount = `NT SERVICE\TrustedInstaller`
	windowsScannerSourceCheck = func(string, string) error { return nil }
	payload := t.TempDir()
	installer = filepath.Join(payload, "install-enterprise.ps1")
	source = filepath.Join(payload, managed.StandaloneWindowsScannerRuntimeName)
	for _, path := range []string{installer, source} {
		if err := os.WriteFile(path, []byte("unsigned "+filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, installer, source
}

// GAP-0919: an installed scanner executable with the staged bytes and an
// admission record is admitted again under the current trust policy. Before,
// matching bytes skipped admission, so a new signer restriction never
// applied to it.
func TestWindowsScannerRuntimeMatchingBytesAreAdmittedAgain(t *testing.T) {
	root, installer, source := stageWindowsScannerRuntimeTest(t)
	windowsEnterpriseInstalledProductVersion = func(*windowsEnterpriseLifecycleOptions) (string, error) { return "", errors.New("not installed") }
	gateway, err := managed.WindowsServiceAccountSID(windowsScannerGatewayAccount)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsScannerRuntimeRoot(root, gateway); err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if err := os.WriteFile(target, staged, 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := windowsEnterpriseFileSHA256(source)
	if err != nil {
		t.Fatal(err)
	}
	// An earlier run admitted these bytes under a looser policy.
	if err := managed.WriteScannerRuntimeAdmission(root, digest); err != nil {
		t.Fatal(err)
	}
	opts := &windowsEnterpriseLifecycleOptions{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustAuthenticode}
	err = installWindowsScannerRuntime(source, opts)
	if err == nil || !strings.Contains(err.Error(), "not admitted by the standalone payload trust policy") {
		t.Fatalf("install = %v, want the trust policy refusal for matching bytes", err)
	}
}

// GAP-1166: the scanner step of a run older than the installed deployment
// leaves the runtime to the run that installed it, and says so.
func TestWindowsScannerRuntimeOlderRunDoesNotReplaceANewerRuntime(t *testing.T) {
	root, installer, _ := stageWindowsScannerRuntimeTest(t)
	windowsEnterpriseInstalledProductVersion = func(*windowsEnterpriseLifecycleOptions) (string, error) { return "1.5.0", nil }
	opts := &windowsEnterpriseLifecycleOptions{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustAuthenticode,
		allowUnsigned: true, productVersion: "1.4.0"}
	result := enterprisestatus.New("upgrade", managed.ProfileStandalone, "windows", "1.4.0")
	applyWindowsStandaloneScannerRuntime(result, opts)
	if _, err := os.Lstat(filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the older run installed its scanner executable: %v", err)
	}
	if len(result.Errors) != 0 || !windowsEnterpriseResultHasWarning(result, "scanner_runtime_superseded") {
		t.Fatalf("errors %+v warnings %+v, want only scanner_runtime_superseded", result.Errors, result.Warnings)
	}
	if got := windowsScannerRuntimeSupersededBy(&windowsEnterpriseLifecycleOptions{productVersion: "1.5.0"}); got != "" {
		t.Fatalf("same release reported as superseded by %q", got)
	}
}
