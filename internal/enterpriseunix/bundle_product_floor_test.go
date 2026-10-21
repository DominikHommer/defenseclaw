// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

func useConfirmedProductFloor(t *testing.T, floor string, err error) {
	t.Helper()
	previous := confirmedBundleProductFloor
	confirmedBundleProductFloor = func(*enterprisebundle.Store) (string, error) { return floor, err }
	t.Cleanup(func() { confirmedBundleProductFloor = previous })
}

// A device that takes signed bundles refuses a rollback below the release
// the confirmed bundle requires, even a deliberate one; without trust
// anchors the rollback stays the administrator's choice.
func TestRollbackBelowTheConfirmedBundleFloorIsRefused(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			useConfirmedProductFloor(t, "1.0.3", nil)
			anchors := h.env.bundleAnchorsPath()
			if err := os.MkdirAll(filepath.Dir(anchors), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(anchors, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			requireError(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.2"), AllowDowngrade: true}), codeProductFloor)
			if record, _ := h.env.loadDeployment(); record.ProductVersion != "1.0.3" {
				t.Fatalf("refused rollback changed the record: %s", record.ProductVersion)
			}
			useConfirmedProductFloor(t, "", errors.New("state unreadable"))
			requireError(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.2"), AllowDowngrade: true}), codeProductFloor)

			// A bundle signed with a lower floor lets the rollback through.
			useConfirmedProductFloor(t, "1.0.2", nil)
			r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.2"), AllowDowngrade: true})
			requireOK(t, r)
			if r.InstalledVersion != "1.0.2" {
				t.Fatalf("rollback to the floor installed %q", r.InstalledVersion)
			}
		})
	}
}

// A --keep-state uninstall removes the deployment record but keeps the trust
// anchors and the confirmed bundle; a reinstall below that bundle's floor is
// refused, one at the floor goes through.
func TestKeepStateReinstallBelowTheConfirmedBundleFloorIsRefused(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			anchors := h.env.bundleAnchorsPath()
			if err := os.MkdirAll(filepath.Dir(anchors), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(anchors, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionUninstall, KeepState: true}))
			if record, _ := h.env.loadDeployment(); record != nil {
				t.Fatalf("--keep-state uninstall kept the deployment record: %+v", record)
			}
			if _, err := os.Lstat(anchors); err != nil {
				t.Fatalf("--keep-state uninstall removed the trust anchors: %v", err)
			}
			useConfirmedProductFloor(t, "1.0.3", nil)
			requireError(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.2")}), codeProductFloor)
			if record, _ := h.env.loadDeployment(); record != nil {
				t.Fatalf("refused reinstall wrote a deployment record: %+v", record)
			}
			r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")})
			requireOK(t, r)
			if r.InstalledVersion != "1.0.3" {
				t.Fatalf("reinstall at the floor installed %q", r.InstalledVersion)
			}
		})
	}
}

func TestBundleProductFloorNeedsTrustAnchors(t *testing.T) {
	h := newTestHost(t, "linux")
	useConfirmedProductFloor(t, "9.9.9", nil)
	if err := h.env.BundleProductFloorRefusal("1.0.0"); err != nil {
		t.Fatalf("no trust anchors: %v; want no floor", err)
	}
}

// A non-purge uninstall on a device with bundle trust anchors keeps a
// root-only copy of the deployed gateway, so the package scripts can run
// floor-check once the installed gateway is gone; a committed reinstall
// removes it. No anchors, a purge, or a gateway that is not the recorded
// binary keep none.
func TestNonPurgeUninstallKeepsTheFloorCheckerForThePackageScripts(t *testing.T) {
	writeAnchors := func(t *testing.T, h *testHost) {
		t.Helper()
		anchors := h.env.bundleAnchorsPath()
		if err := os.MkdirAll(filepath.Dir(anchors), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(anchors, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			installed := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			writeAnchors(t, h)
			r := h.run(Options{Action: ActionUninstall, KeepState: true})
			requireOK(t, r)
			if hasWarning(r, codeFloorCheckerNotKept) {
				t.Fatalf("keep-state uninstall did not keep the floor checker: %+v", r.Warnings)
			}
			if !strings.Contains(strings.Join(r.Changes, "\n"), filepath.Join(h.env.Layout.LifecycleDir, floorCheckerDir)) {
				t.Fatalf("the uninstall summary does not name the kept floor checker: %q", r.Changes)
			}
			if _, err := os.Lstat(installed); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the installed gateway is still there (%v); the case needs it gone", err)
			}
			checker := h.env.floorCheckerPath()
			got, err := os.ReadFile(checker)
			if err != nil {
				t.Fatalf("no floor checker after a keep-state uninstall: %v", err)
			}
			if string(got) != binGateway+" 1.0.3\n" {
				t.Fatalf("floor checker holds %q, not the deployed gateway", got)
			}
			for path, mode := range map[string]os.FileMode{checker: 0o700, filepath.Dir(checker): 0o700} {
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != mode {
					t.Fatalf("%s mode %v, want %v", path, info.Mode().Perm(), mode)
				}
				if owner, ok := h.owners[path]; ok && owner != [2]int{0, 0} {
					t.Fatalf("%s owned by %v, want root", path, owner)
				}
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			if _, err := os.Lstat(filepath.Dir(checker)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a committed reinstall kept the floor checker: %v", err)
			}
		})
	}
	t.Run("no anchors", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
		requireOK(t, h.run(Options{Action: ActionUninstall, KeepState: true}))
		if _, err := os.Lstat(h.env.floorCheckerPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("kept a floor checker without trust anchors: %v", err)
		}
	})
	t.Run("purge", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
		writeAnchors(t, h)
		requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
		if _, err := os.Lstat(h.env.floorCheckerPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a purge kept the floor checker: %v", err)
		}
	})
	t.Run("not the recorded gateway", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
		writeAnchors(t, h)
		if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway)), []byte("replaced\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		r := h.run(Options{Action: ActionUninstall, KeepState: true})
		if !hasWarning(r, codeFloorCheckerNotKept) {
			t.Fatalf("no %s warning for a replaced gateway: %+v", codeFloorCheckerNotKept, r.Warnings)
		}
		if _, err := os.Lstat(h.env.floorCheckerPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("kept a gateway the record does not name: %v", err)
		}
	})
}
