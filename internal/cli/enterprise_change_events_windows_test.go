// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// stubWindowsChangeSpool records change events into a plain folder of the
// test, as an elevated caller.
func stubWindowsChangeSpool(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), enterprisestatus.ChangeEventsDirName)
	savedSpool, savedElevated := windowsChangeSpool, windowsSecretIsElevated
	windowsChangeSpool = func(managed.StandaloneLayout) (enterprisestatus.ChangeSpool, error) {
		return enterprisestatus.ChangeSpool{Dir: dir}, nil
	}
	windowsSecretIsElevated = func() bool { return true }
	t.Cleanup(func() { windowsChangeSpool, windowsSecretIsElevated = savedSpool, savedElevated })
	return dir
}

func TestWindowsAnchorsProfilePreflightRefusalIsAuditedOnlyOnProvenInstalledHost(t *testing.T) {
	for _, state := range []winpath.EnterpriseDeploymentState{winpath.EnterpriseDeploymentInstalled,
		winpath.EnterpriseDeploymentAbsent, winpath.EnterpriseDeploymentTombstone, winpath.EnterpriseDeploymentUnknown} {
		for _, elevated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/elevated=%t", state, elevated), func(t *testing.T) {
				stubWindowsEnterpriseDeployments(t, map[string]winpath.EnterpriseDeploymentState{managed.ProfileStandalone: state})
				stubWindowsBundleHost(t)
				spool := stubWindowsChangeSpool(t)
				saved := windowsEnterpriseIsElevated
				windowsEnterpriseIsElevated = func() bool { return elevated }
				t.Cleanup(func() { windowsEnterpriseIsElevated = saved })
				cmd, out := windowsBundleCommand()
				opts := &windowsEnterpriseLifecycleOptions{profile: managed.ProfileStandalone, jsonOutput: true,
					trustAnchors: filepath.Join(t.TempDir(), "unread-anchors.json"), brokerBinary: "incompatible-broker.exe"}
				if err := runWindowsEnterpriseLifecycle(t.Context(), cmd, "ensure", opts); err == nil {
					t.Fatalf("invalid broker option accepted: %s", out)
				}
				ids := enterprisestatus.ListChangeEventIDs(spool)
				want := 0
				if elevated && state == winpath.EnterpriseDeploymentInstalled {
					want = 1
				}
				if len(ids) != want {
					t.Fatalf("profile refusal events = %v, want %d; %s", ids, want, out)
				}
				if want == 1 {
					ev, err := enterprisestatus.ReadChangeEvent(filepath.Join(spool, ids[0]+".json"))
					if err != nil || ev.Kind != enterprisestatus.ChangeKindTrustAnchors || ev.Outcome != enterprisestatus.ChangeRefused {
						t.Fatalf("profile refusal audit = %+v, %v", ev, err)
					}
				}
			})
		}
	}
}

// A TRUSTANCHORS= run refused because bundle.lock is busy records one
// refused anchor install, as Linux and macOS do.
func TestWindowsAnchorsLockRefusalRecordsOneChangeEvent(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	layout := stubWindowsBundleHost(t)
	spool := stubWindowsChangeSpool(t)
	unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
	if err != nil {
		t.Fatalf("hold bundle.lock: %v", err)
	}
	t.Cleanup(unlock)
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{trustAnchors: e.anchors, profile: managed.ProfileStandalone,
		jsonOutput: true, installedBeforeRun: true}
	done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
	cleanupPreparedWindowsBundle(t, opts)
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitBusy {
		t.Fatalf("held lock: done=%v exit=%d out=%s", done, commandExitCode(err), out)
	}
	ids := enterprisestatus.ListChangeEventIDs(spool)
	if len(ids) != 1 {
		t.Fatalf("change events = %v, want one refused anchor install", ids)
	}
	ev, err := enterprisestatus.ReadChangeEvent(filepath.Join(spool, ids[0]+".json"))
	if err != nil || ev.Kind != enterprisestatus.ChangeKindTrustAnchors || ev.Outcome != enterprisestatus.ChangeRefused ||
		ev.ReasonCode != "lifecycle_busy" {
		t.Fatalf("change event = %+v, %v", ev, err)
	}
}
