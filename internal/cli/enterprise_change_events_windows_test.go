// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// stubWindowsChangeSpool records change events into a plain folder of the
// test, as an elevated caller. It returns the spool and its state folder
// (the reservations).
func stubWindowsChangeSpool(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), enterprisestatus.ChangeEventsDirName)
	state := t.TempDir()
	savedSpool, savedElevated := windowsChangeSpool, windowsSecretIsElevated
	windowsChangeSpool = func(managed.StandaloneLayout) (enterprisestatus.ChangeSpool, error) {
		return enterprisestatus.ChangeSpool{Dir: dir, StateDir: state}, nil
	}
	windowsSecretIsElevated = func() bool { return true }
	t.Cleanup(func() { windowsChangeSpool, windowsSecretIsElevated = savedSpool, savedElevated })
	return dir, state
}

func windowsChangeEvents(t *testing.T, spool string) []enterprisestatus.ChangeEvent {
	t.Helper()
	var out []enterprisestatus.ChangeEvent
	for _, id := range enterprisestatus.ListChangeEventIDs(spool) {
		ev, err := enterprisestatus.ReadChangeEvent(filepath.Join(spool, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

func assertNoWindowsChangeReservations(t *testing.T, state string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(state, "change-reservations"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("change reservations left: %v", entries)
	}
}

func assertOneRefusedAnchorInstall(t *testing.T, spool, code string) {
	t.Helper()
	events := windowsChangeEvents(t, spool)
	if len(events) != 1 {
		t.Fatalf("change events = %+v, want one refused anchor install", events)
	}
	ev := events[0]
	if ev.Kind != enterprisestatus.ChangeKindTrustAnchors || ev.Outcome != enterprisestatus.ChangeRefused ||
		ev.SHA256 != "" || (code != "" && ev.ReasonCode != code) || ev.ReasonCode == "" {
		t.Fatalf("change event = %+v, want a refused anchor install (%q) with no installed file", ev, code)
	}
}

func TestWindowsAnchorPreflightRefusalRecordsOneChangeEvent(t *testing.T) {
	stubWindowsBundleHost(t)
	spool, state := stubWindowsChangeSpool(t)
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{trustAnchors: "anchors.json", configPath: "config.yaml",
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts)
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs {
		t.Fatalf("incompatible arguments: done=%v, err=%v, output=%s", done, err, out)
	}
	assertOneRefusedAnchorInstall(t, spool, "bundle_required")
	assertNoWindowsChangeReservations(t, state)
	// Fresh and unelevated callers cannot create an installed-host audit.
	opts.installedBeforeRun = false
	_, _ = prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts)
	opts.installedBeforeRun = true
	windowsSecretIsElevated = func() bool { return false }
	_, _ = prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts)
	assertOneRefusedAnchorInstall(t, spool, "bundle_required")
}

// An ensure with TRUSTANCHORS= whose BUNDLE= is rejected after the anchors
// were staged installs no anchors and records one refused anchor install
// with the bundle's refusal code. Before, the run staged the anchors and
// returned through the bundle refusal with no change event.
func TestWindowsStagedAnchorsOfARejectedBundleRecordOneRefusal(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	layout := stubWindowsBundleHost(t)
	spool, state := stubWindowsChangeSpool(t)
	rejected := filepath.Join(e.dir, "rejected.dcbundle")
	writeBundleTestFile(t, rejected, []byte("not a policy bundle"))
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: rejected, trustAnchors: e.anchors, profile: managed.ProfileStandalone,
		jsonOutput: true, installedBeforeRun: true}
	done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
	cleanupPreparedWindowsBundle(t, opts)
	if !done || err == nil {
		t.Fatalf("a rejected bundle was accepted: done=%v err=%v\n%s", done, err, out)
	}
	assertWindowsBundleInstalledAnchors(t, layout, nil, "after the rejected bundle")
	assertOneRefusedAnchorInstall(t, spool, "")
	assertNoWindowsChangeReservations(t, state)
}

// A run that returns after prepare without finish installed none of the
// anchors it staged: release records one refused install (interrupted),
// once.
func TestWindowsStagedAnchorsOfARunThatEndsBeforeFinishRecordOneRefusal(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	spool, state := stubWindowsChangeSpool(t)
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors, profile: managed.ProfileStandalone,
		jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("prepare ended: %v\n%s", err, out)
	}
	cleanupPreparedWindowsBundle(t, opts)
	if events := windowsChangeEvents(t, spool); len(events) != 0 {
		t.Fatalf("recorded %+v before the run ended", events)
	}
	run := opts.bundle
	run.release()
	run.release()
	assertWindowsBundleInstalledAnchors(t, layout, nil, "after the run ended")
	assertOneRefusedAnchorInstall(t, spool, "interrupted")
	assertNoWindowsChangeReservations(t, state)
}

// A TRUSTANCHORS= run refused because bundle.lock is busy records one
// refused anchor install, as Linux and macOS do.
func TestWindowsAnchorsLockRefusalRecordsOneChangeEvent(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	layout := stubWindowsBundleHost(t)
	spool, _ := stubWindowsChangeSpool(t)
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

// The real Windows creator must stamp both directories, including the
// protected flag, on a never-bundled install and on an inherited parent.
func TestWindowsChangeSpoolProtectsTheBundleParent(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		t.Fatal(err)
	}
	for _, inherited := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "inherited"}[inherited], func(t *testing.T) {
			layout := managed.StandaloneLayout{ConfigDir: filepath.Join(windowsBundleScratchDir(t), "etc")}
			bundles := filepath.Join(layout.ConfigDir, "bundles")
			if inherited {
				if err := os.MkdirAll(bundles, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			spool, err := windowsChangeSpool(layout)
			if err != nil {
				t.Fatal(err)
			}
			if err := spool.Prepare(spool.Dir); err != nil {
				t.Fatal(err)
			}
			for path, descriptor := range map[string]string{
				bundles:   windowsBundleDirectorySDDL(service.String()),
				spool.Dir: windowsBundleVersionSDDL(service.String(), true),
			} {
				actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := windows.SecurityDescriptorFromString(descriptor)
				if err != nil {
					t.Fatal(err)
				}
				equal, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
				if err != nil || !equal {
					t.Fatalf("%s ACL=%s, want %s: %v", path, actual.String(), descriptor, err)
				}
			}
		})
	}
}
