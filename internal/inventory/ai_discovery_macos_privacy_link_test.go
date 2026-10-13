// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func packageScanLinkService(t *testing.T, home, root string, catalog []AISignature, secureClient bool) *ContinuousDiscoveryService {
	t.Helper()
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: t.TempDir(), HomeDir: home,
		ScanRoots: []string{root}, MaxFilesPerScan: 100, MaxFileBytes: 1 << 20,
		SecureClient: secureClient,
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)
	return svc
}

func packageScanAISignals(t *testing.T, svc *ContinuousDiscoveryService) ([]AISignal, int) {
	t.Helper()
	signals, _, err := svc.detectPackageManifests(context.Background())
	if err != nil {
		t.Fatalf("detectPackageManifests: %v", err)
	}
	count := 0
	for _, signal := range signals {
		if signal.Component != nil && signal.Component.Name == "ai" {
			count++
		}
	}
	return signals, count
}

func mustPackageScanLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// linkFreeTempDir returns a test folder whose path holds no link. macOS keeps
// the default temp folder under /var, a link to /private/var, and the root
// check compares the resolved path with the home folder as the service names it.
func linkFreeTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPackageScanRootThroughParentLinkKeepsMacOSPrivacySkip(t *testing.T) {
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

	cases := []struct {
		name, protectedFolder string
		root                  func(t *testing.T, home, outside, app string) string
	}{
		{"absolute parent link", "Documents", func(t *testing.T, home, _, app string) string {
			mustPackageScanLink(t, filepath.Dir(app), filepath.Join(home, "work"))
			return filepath.Join(home, "work", "app")
		}},
		{"relative parent link", "Documents", func(t *testing.T, home, _, _ string) string {
			mustPackageScanLink(t, "../Documents", filepath.Join(home, "work", "linked"))
			return filepath.Join(home, "work", "linked", "app")
		}},
		{"two links", "Documents", func(t *testing.T, home, _, app string) string {
			mustPackageScanLink(t, filepath.Dir(app), filepath.Join(home, "b"))
			mustPackageScanLink(t, filepath.Join(home, "b"), filepath.Join(home, "a"))
			return filepath.Join(home, "a", "app")
		}},
		{"last component is a link", "Documents", func(t *testing.T, home, _, app string) string {
			mustPackageScanLink(t, app, filepath.Join(home, "appLink"))
			return filepath.Join(home, "appLink")
		}},
		{"link outside home", "Documents", func(t *testing.T, home, outside, app string) string {
			mustPackageScanLink(t, filepath.Dir(app), filepath.Join(outside, "linked"))
			return filepath.Join(outside, "linked", "app")
		}},
		{"nested protected folder", "Library/Containers", func(t *testing.T, home, _, _ string) string {
			mustPackageScanLink(t, "../Library/Containers", filepath.Join(home, "work", "linked"))
			return filepath.Join(home, "work", "linked", "app")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, outside := linkFreeTempDir(t), linkFreeTempDir(t)
			app := filepath.Join(home, tc.protectedFolder, "app")
			mustWrite(t, filepath.Join(app, "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
			root := tc.root(t, home, outside, app)
			svc := packageScanLinkService(t, home, root, catalog, false)
			signals, projects := packageScanAISignals(t, svc)
			if projects != 0 || len(signals) != 0 || !svc.tccSkipped {
				t.Fatalf("protected root %s: %d ai projects, %d signals, privacy skipped=%t; want 0, 0, true", root, projects, len(signals), svc.tccSkipped)
			}
			if !svc.tccSkippedPaths[hashPath(filepath.Join(home, tc.protectedFolder))] {
				t.Fatal("protected folder was not recorded as a privacy skip")
			}
		})
	}

	home := linkFreeTempDir(t)
	protectedApp := filepath.Join(home, "Documents", "app")
	mustWrite(t, filepath.Join(protectedApp, "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
	mustPackageScanLink(t, filepath.Join(home, "Documents"), filepath.Join(home, "linked"))
	linkedRoot := filepath.Join(home, "linked", "app")
	for _, control := range []struct {
		name, goos     string
		fullDiskAccess bool
		secureClient   bool
	}{
		{"Full Disk Access", "darwin", true, false},
		{"off macOS", "linux", false, false},
		{"Secure Client", "darwin", false, true},
	} {
		t.Run(control.name, func(t *testing.T) {
			discoveryGOOS = control.goos
			macOSFullDiskAccess = func() bool { return control.fullDiskAccess }
			svc := packageScanLinkService(t, home, linkedRoot, catalog, control.secureClient)
			_, projects := packageScanAISignals(t, svc)
			if projects != 1 || svc.tccSkipped {
				t.Fatalf("%s: %d ai projects, privacy skipped=%t; want 1, false", control.name, projects, svc.tccSkipped)
			}
		})
	}
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return false }
	unprotectedApp := filepath.Join(home, "work", "app")
	mustWrite(t, filepath.Join(unprotectedApp, "package.json"), `{"dependencies": {"ai": "^3.0.0"}}`)
	mustPackageScanLink(t, filepath.Join(home, "work"), filepath.Join(home, "projLink"))
	for _, control := range []struct{ name, root string }{
		{"unprotected link", filepath.Join(home, "projLink", "app")},
		{"plain unprotected root", unprotectedApp},
		{"root above protected folder", home},
	} {
		t.Run(control.name, func(t *testing.T) {
			svc := packageScanLinkService(t, home, control.root, catalog, false)
			_, projects := packageScanAISignals(t, svc)
			if projects != 1 {
				t.Fatalf("%s: %d ai projects, want the unprotected project only", control.name, projects)
			}
			if control.root == home && !svc.tccSkipped {
				t.Fatal("the walk did not skip Documents below the home root")
			}
		})
	}
}

func TestMacOSTCCRootSkippedResolvesRelativeLinkFromRealParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks need privileges on Windows")
	}
	oldOS, oldFDA := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = oldOS, oldFDA })
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return false }
	home := linkFreeTempDir(t)
	if err := os.MkdirAll(filepath.Join(home, "work", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	mustPackageScanLink(t, filepath.Join(home, "work", "nested"), filepath.Join(home, "alias"))
	mustPackageScanLink(t, "../../Documents", filepath.Join(home, "work", "nested", "jump"))
	root := filepath.Join(home, "alias", "jump", "app")
	lexicalTarget := filepath.Clean(filepath.Join(home, "alias", "../../Documents"))
	if macOSTCCProtectedPath(lexicalTarget, []string{home}) {
		t.Fatal("the lexical link target should be outside the protected home folder")
	}
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home}}
	if !svc.macOSTCCRootSkipped(root) || !svc.tccSkippedPaths[hashPath(filepath.Join(home, "Documents"))] {
		t.Fatal("relative target did not climb from the link's resolved parent into Documents")
	}
	mustPackageScanLink(t, "../../Documents", filepath.Join(home, "plain", "jump"))
	plainSvc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home}}
	if plainSvc.macOSTCCRootSkipped(filepath.Join(home, "plain", "jump", "app")) || plainSvc.tccSkipped {
		t.Fatal("a link outside the protected home folder was treated as protected")
	}
}

func TestMacOSTCCRootSkippedStopsAtMissingProtectedFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks need privileges on Windows")
	}
	oldOS, oldFDA := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = oldOS, oldFDA })
	discoveryGOOS = "darwin"
	macOSFullDiskAccess = func() bool { return false }
	home := linkFreeTempDir(t)
	mustPackageScanLink(t, filepath.Join(home, "Documents", "missing", "deeper"), filepath.Join(home, "route"))
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home}}
	if !svc.macOSTCCRootSkipped(filepath.Join(home, "route", "app")) ||
		!svc.tccSkippedPaths[hashPath(filepath.Join(home, "Documents"))] {
		t.Fatal("the missing protected prefix was not skipped before access")
	}
}
