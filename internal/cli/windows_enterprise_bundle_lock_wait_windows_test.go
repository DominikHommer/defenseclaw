// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// prepareWithHeldBundleLock runs prepare for a BUNDLE= delivery while this
// test holds bundle.lock through a second handle, released after holdFor
// (never when holdFor is 0).
func prepareWithHeldBundleLock(t *testing.T, wait, holdFor time.Duration) (*windowsEnterpriseLifecycleOptions, string, bool, error) {
	t.Helper()
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
	if err != nil {
		t.Fatalf("hold bundle.lock: %v", err)
	}
	released := make(chan struct{})
	if holdFor > 0 {
		go func() { time.Sleep(holdFor); unlock(); close(released) }()
		t.Cleanup(func() { <-released })
	} else {
		t.Cleanup(unlock)
	}
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true, bundleLockWait: wait}
	done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
	cleanupPreparedWindowsBundle(t, opts)
	return opts, out.String(), done, err
}

// A4: without --lock-wait a held bundle.lock is lifecycle_busy (1618) at
// once, as before.
func TestWindowsBundleApplyWithoutLockWaitFailsAtOnce(t *testing.T) {
	start := time.Now()
	_, out, done, err := prepareWithHeldBundleLock(t, 0, 0)
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitBusy || !strings.Contains(out, `"lifecycle_busy"`) {
		t.Fatalf("held lock without --lock-wait: done=%v exit=%d out=%s", done, commandExitCode(err), out)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("a run without --lock-wait waited %s", elapsed)
	}
}

// A4: --lock-wait waits for bundle.lock and then runs.
func TestWindowsBundleApplyLockWaitTakesTheReleasedLock(t *testing.T) {
	opts, out, done, err := prepareWithHeldBundleLock(t, 30*time.Second, 300*time.Millisecond)
	if done || err != nil || opts.bundle == nil || opts.bundle.prepared == nil {
		t.Fatalf("--lock-wait 30s with the lock released after 300ms: done=%v err=%v out=%s", done, err, out)
	}
}

// A4: a wait that expires is lifecycle_busy 1618 and names the wait.
func TestWindowsBundleApplyLockWaitExpiresBusy(t *testing.T) {
	_, out, done, err := prepareWithHeldBundleLock(t, 300*time.Millisecond, 0)
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitBusy || !strings.Contains(out, `"lifecycle_busy"`) ||
		!strings.Contains(out, "still held after --lock-wait 300ms") {
		t.Fatalf("expired --lock-wait: done=%v exit=%d out=%s", done, commandExitCode(err), out)
	}
}

// A4: apply forwards --lock-wait, not --reason, and refuses a wait outside
// 0..15m with 1639 before anything runs.
func TestWindowsBundleApplyForwardsLockWaitOnly(t *testing.T) {
	cmd := newEnterpriseBundleApplyCommand()
	if err := cmd.Flags().Parse([]string{"--bundle", `C:\x.dcbundle`, "--reason", "management", "--lock-wait", "10m"}); err != nil {
		t.Fatal(err)
	}
	opts := &bundleApplyOptions{bundle: `C:\x.dcbundle`, reason: "management", lockWait: 10 * time.Minute}
	lifecycle, err := windowsBundleApplyLifecycleOptions(cmd, opts)
	if err != nil || lifecycle.bundleLockWait != 10*time.Minute || lifecycle.bundlePath != `C:\x.dcbundle` {
		t.Fatalf("options %+v, %v", lifecycle, err)
	}
	over := &cobra.Command{Use: "apply"}
	addLockWaitFlag(over.Flags(), &opts.lockWait)
	if err := over.Flags().Parse([]string{"--lock-wait", "16m"}); err != nil {
		t.Fatal(err)
	}
	if _, err := windowsBundleApplyLifecycleOptions(over, opts); commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs ||
		!strings.Contains(err.Error(), "--lock-wait takes at most 15m, not 16m") {
		t.Fatalf("--lock-wait 16m: %v (exit %d)", err, commandExitCode(err))
	}
}
