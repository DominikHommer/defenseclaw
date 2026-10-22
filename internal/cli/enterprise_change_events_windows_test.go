// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

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

func TestWindowsChangeSyntaxRefusalsAreAudited(t *testing.T) {
	root := t.TempDir()
	layout := managed.StandaloneLayout{ConfigDir: filepath.Join(root, "etc"), LifecycleDir: filepath.Join(root, "install")}
	stubWindowsSecretHost(t, layout)
	spool, state := stubWindowsChangeSpool(t)
	savedSecure := bundleSecureClient
	bundleSecureClient = func() bool { return false }
	t.Cleanup(func() { bundleSecureClient = savedSecure })
	for _, tc := range []struct {
		action string
		args   []string
	}{
		{"set", []string{"--name", "BAD_NAME", "--unknown"}},
		{"set", []string{"--name"}},
		{"set", []string{"--from-stdin"}},
		{"remove", []string{"--name", "qa-token", "extra"}},
		{"remove", []string{"--lock-wait=invalid"}},
		{"ensure", []string{"--trust-anchors", "unread-input.json", "--unknown"}},
		{"ensure", []string{"--unknown", "--trust-anchors=unread-input.json"}},
		{"ensure", []string{"--trust-anchors"}},
		{"ensure", []string{"--trust-anchors=unread-input.json", "extra"}},
		{"ensure", []string{"--unknown", "--config", "--", "--trust-anchors=unread-input.json"}},
	} {
		t.Run(tc.action+"/"+strings.Join(tc.args, " "), func(t *testing.T) {
			before := windowsChangeEvents(t, spool)
			cmd := newEnterpriseSecretCommand(tc.action, "")
			kind, action := enterprisestatus.ChangeKindSecret, tc.action
			if tc.action == "ensure" {
				cmd = newWindowsEnterpriseLifecycleCommand(tc.action)
				kind, action = enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall
			}
			cmd.RunE = func(*cobra.Command, []string) error {
				t.Fatal("syntax error reached the change implementation")
				return nil
			}
			secretRawArgs = func() []string { return tc.args }
			cmd.SetArgs(tc.args)
			input := strings.NewReader("credential-value-marker\n")
			cmd.SetIn(input)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			if err := cmd.Execute(); commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs {
				t.Fatalf("syntax error = %v", err)
			}
			if input.Len() != len("credential-value-marker\n") {
				t.Fatal("a syntax refusal read the credential")
			}
			events := windowsChangeEvents(t, spool)
			if len(events) != len(before)+1 {
				t.Fatalf("got %d change events, want %d", len(events), len(before)+1)
			}
			ev := events[len(events)-1]
			if ev.Kind != kind || ev.Action != action || ev.Outcome != enterprisestatus.ChangeRefused ||
				ev.ReasonCode != "invalid_arguments" || ev.Actor == "" || ev.Validate() != nil || ev.SecretName == "BAD_NAME" {
				t.Fatalf("syntax refusal = %+v", ev)
			}
			assertNoWindowsChangeReservations(t, state)
		})
	}
	before := windowsChangeEvents(t, spool)
	for _, mode := range []string{"per-user", "standard-account", "secure-client", "status", "after-separator", "flag-value", "flag-value-stray"} {
		windowsSecretIsElevated = func() bool { return mode != "standard-account" }
		windowsSecretDeploymentInstalled = func() (bool, error) { return mode != "per-user", nil }
		bundleSecureClient = func() bool { return mode == "secure-client" }
		cmd := newEnterpriseSecretCommand("set", "")
		if mode == "status" {
			cmd = newEnterpriseSecretCommand("status", "")
		}
		args := []string{"--unknown"}
		switch mode {
		case "after-separator":
			args = []string{"--", "--trust-anchors=unread-input.json"}
		case "flag-value":
			// --config takes "--trust-anchors" as its value.
			args = []string{"--profile", "standalone", "--config", "--trust-anchors", "--unknown"}
		case "flag-value-stray":
			args = []string{"--bundle", "--trust-anchors", "extra"}
		}
		if strings.HasPrefix(mode, "after-") || strings.HasPrefix(mode, "flag-") {
			cmd = newWindowsEnterpriseLifecycleCommand("ensure")
		}
		raw := append([]string{"enterprise", "windows", "ensure"}, args...)
		secretRawArgs = func() []string { return raw }
		cmd.SetArgs(args)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs {
			t.Fatalf("%s syntax error = %v", mode, err)
		}
	}
	if after := windowsChangeEvents(t, spool); len(after) != len(before) {
		t.Fatal("a per-user, unprivileged, Secure Client, read-only, literal-argument or flag-value error wrote a managed event")
	}
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
