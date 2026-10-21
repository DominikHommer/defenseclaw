// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"path/filepath"
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

func TestBundleProductFloorNeedsTrustAnchors(t *testing.T) {
	h := newTestHost(t, "linux")
	useConfirmedProductFloor(t, "9.9.9", nil)
	if err := h.env.BundleProductFloorRefusal("1.0.0"); err != nil {
		t.Fatalf("no trust anchors: %v; want no floor", err)
	}
}
