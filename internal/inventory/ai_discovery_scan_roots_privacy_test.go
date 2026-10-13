// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestPackageScanPrivacySkippedConfiguredRootsDoNotFallBackToHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks need privileges on Windows")
	}
	oldOS, oldFDA := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = oldOS, oldFDA })
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return false }
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}

	home := linkFreeTempDir(t)
	protected := filepath.Join(home, "Documents", "app")
	work := filepath.Join(home, "work", "app")
	mustWrite(t, filepath.Join(protected, "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
	mustWrite(t, filepath.Join(work, "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
	mustWrite(t, filepath.Join(home, "other", "x", "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
	mustPackageScanLink(t, filepath.Join(home, "Documents"), filepath.Join(home, "code"))
	linked := filepath.Join(home, "code", "app")
	missing := filepath.Join(home, "missing")

	for _, tc := range []struct {
		name  string
		roots []string
	}{
		{"lexical protected root", []string{protected}},
		{"parent link into protected root", []string{linked}},
		{"protected root and missing root", []string{protected, missing}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := packageScanLinkService(t, home, tc.roots[0], catalog, false)
			svc.opts.ScanRoots = tc.roots
			roots := svc.scanRoots()
			signals, projects := packageScanAISignals(t, svc)
			if len(roots) != 0 || projects != 0 || len(signals) != 0 {
				t.Fatalf("privacy-skipped roots = %v, %d ai projects, %d signals; want no roots or signals", roots, projects, len(signals))
			}
			if !svc.tccSkipped || !svc.tccSkippedPaths[hashPath(filepath.Join(home, "Documents"))] {
				t.Fatal("Documents privacy skip was not recorded")
			}
		})
	}

	t.Run("protected and unprotected roots", func(t *testing.T) {
		svc := packageScanLinkService(t, home, protected, catalog, false)
		svc.opts.ScanRoots = []string{protected, work}
		roots := svc.scanRoots()
		if len(roots) != 1 || roots[0] != work {
			t.Fatalf("scanRoots() = %v, want only %s", roots, work)
		}
		signals, projects := packageScanAISignals(t, svc)
		if projects != 1 || len(signals) != 1 || !svc.tccSkipped {
			t.Fatalf("mixed roots found %d ai projects and %d signals, privacy skipped=%t; want 1, 1, true", projects, len(signals), svc.tccSkipped)
		}
	})

	t.Run("missing root without privacy skip still falls back", func(t *testing.T) {
		svc := packageScanLinkService(t, home, missing, catalog, false)
		roots := svc.scanRoots()
		if len(roots) != 1 || roots[0] != home || svc.tccSkipped {
			t.Fatalf("scanRoots() = %v, privacy skipped=%t; want home fallback without a privacy skip", roots, svc.tccSkipped)
		}
		_, projects := packageScanAISignals(t, svc)
		if projects != 2 {
			t.Fatalf("home fallback found %d ai projects, want two unprotected projects", projects)
		}
	})
}

func TestPackageScanPrivacySkippedRootDoesNotFallBackAcrossHomes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks need privileges on Windows")
	}
	oldOS, oldFDA := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = oldOS, oldFDA })
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return false }
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}

	h1, h2 := linkFreeTempDir(t), linkFreeTempDir(t)
	protected := filepath.Join(h1, "Documents", "app")
	mustWrite(t, filepath.Join(protected, "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
	for _, home := range []string{h1, h2} {
		mustWrite(t, filepath.Join(home, "work", "app", "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
	}
	svc := packageScanLinkService(t, h1, protected, catalog, false)
	svc.opts.HomeDirs = []string{h1, h2}
	roots := svc.scanRoots()
	signals, projects := packageScanAISignals(t, svc)
	if len(roots) != 0 || projects != 0 || len(signals) != 0 || !svc.tccSkipped {
		t.Fatalf("multi-home roots = %v, %d ai projects, %d signals, privacy skipped=%t; want no roots or signals and a privacy skip", roots, projects, len(signals), svc.tccSkipped)
	}
}
