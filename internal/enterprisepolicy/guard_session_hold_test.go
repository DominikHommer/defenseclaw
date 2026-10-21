// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Review P2 (GAP-0352, 1.0.4 loop round 4): a lifecycle that could not
// replace or close the record folder (a Windows root a retained handle
// keeps from being moved, a lifecycle without SeRestorePrivilege, a macOS
// root whose access list it could not take away) leaves its hold next to
// the folder, and the hook allows nothing during an outage while anything
// is at the hold path, whatever the folder holds: an allow of the current
// generation, or an older generation file and its allow that an account put
// back. Releasing the hold lets the next current allow prove the process
// again. A lifecycle that bumps and releases while the hook checks never
// lets an allow read during the hold pass: the hook reads the generation
// again after the hold.
func TestPublishedSessionHoldBlocksEveryOutageAllow(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	check := func() error {
		t.Helper()
		got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		if got.Deny {
			t.Fatalf("a hold must not turn into a block with a reason: %+v", got)
		}
		return err
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatalf("an allow of the current generation proves the process: %v", err)
	}
	hold, ok := PublishedSessionHoldPath(root)
	if !ok || hold != filepath.Clean(root)+".hold" || filepath.Dir(hold) != filepath.Dir(filepath.Clean(root)) {
		t.Fatalf("the hold is next to the folder: %q %v", hold, ok)
	}
	for _, bad := range []string{"", "relative/sessions", "/"} {
		if _, ok := PublishedSessionHoldPath(bad); ok {
			t.Fatalf("%q has no hold path", bad)
		}
		if !PublishedSessionHeld(bad) {
			t.Fatalf("a folder without a hold path counts as held: %q", bad)
		}
	}

	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if !PublishedSessionHeld(root) {
		t.Fatal("the hold must be in place")
	}
	if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) || !strings.Contains(err.Error(), "holds the record folder") {
		t.Fatalf("a held folder proves nothing: %v", err)
	}
	// The gateway keeps publishing during the hold: its allows prove
	// nothing until the hold is released.
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("an allow published during the hold proves nothing: %v", err)
	}
	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatalf("holding a held folder again is not an error: %v", err)
	}
	if err := ReleasePublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if PublishedSessionHeld(root) {
		t.Fatal("the hold must be gone")
	}
	if err := check(); err != nil {
		t.Fatalf("after the release the current allow proves the process: %v", err)
	}
	if err := ReleasePublishedSessionRecords(root); err != nil {
		t.Fatalf("releasing a folder that is not held is not an error: %v", err)
	}

	// Anything at the hold path holds: a folder, a link, an empty file.
	for name, plant := range map[string]func() error{
		"folder":     func() error { return os.Mkdir(hold, 0o700) },
		"empty file": func() error { return os.WriteFile(hold, nil, 0o600) },
		"link":       func() error { return os.Symlink(filepath.Join(t.TempDir(), "missing"), hold) },
	} {
		if err := plant(); err != nil {
			if name == "link" {
				t.Logf("no link here: %v", err)
				continue
			}
			t.Fatal(err)
		}
		if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("%s at the hold path must hold: %v", name, err)
		}
		if err := ReleasePublishedSessionRecords(root); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := check(); err != nil {
			t.Fatalf("%s: after the release the allow proves the process: %v", name, err)
		}
	}

	// A hold that cannot be checked holds.
	previous := publishedSessionHoldLstat
	t.Cleanup(func() { publishedSessionHoldLstat = previous })
	publishedSessionHoldLstat = func(string) (os.FileInfo, error) { return nil, errors.New("access is denied") }
	if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a hold that cannot be checked must hold: %v", err)
	}

	// An account put an older generation file and its allow back while the
	// folder was held; the lifecycle then bumps and releases right before
	// the hook checks the hold. The hook read the restored generation, so
	// only its second read of the generation refuses the allow.
	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	publishedSessionHoldLstat = func(path string) (os.FileInfo, error) {
		publishedSessionHoldLstat = previous
		if err := BumpPublishedSessionGeneration(root); err != nil {
			t.Fatal(err)
		}
		if err := ReleasePublishedSessionRecords(root); err != nil {
			t.Fatal(err)
		}
		return previous(path)
	}
	if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("an allow read while the folder was held must not pass once the lifecycle finished: %v", err)
	}
	if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) || !strings.Contains(err.Error(), "earlier generation") {
		t.Fatalf("after the lifecycle's bump the old allow proves nothing: %v", err)
	}
}

// The floor a replaced record folder hands to the new one is its trusted
// generation, and nothing when that is missing, untrusted or far ahead of
// the clock.
func TestPublishedSessionGenerationFloor(t *testing.T) {
	root := publishedSessionTestRoot(t)
	if floor := PublishedSessionGenerationFloor(root); floor.UnixNano() != publishedSessionTestGeneration(t, root) {
		t.Fatalf("the floor is the current generation: %v", floor)
	}
	path, _ := PublishedSessionGenerationPath(root)
	ahead := time.Now().Add(48 * time.Hour)
	if err := os.Chtimes(path, ahead, ahead); err != nil {
		t.Fatal(err)
	}
	if floor := PublishedSessionGenerationFloor(root); !floor.IsZero() {
		t.Fatalf("a generation two days ahead is not carried: %v", floor)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if floor := PublishedSessionGenerationFloor(root); !floor.IsZero() {
		t.Fatalf("a missing generation has no floor: %v", floor)
	}
}
