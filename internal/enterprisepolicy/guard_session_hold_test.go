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
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
	holdDir, _ := PublishedSessionHoldDir(root)
	if !ok || hold != filepath.Join(holdDir, filepath.Base(root)+".hold") {
		t.Fatalf("the hold is in the hold folder: %q %v", hold, ok)
	}
	publishedSessionTestHoldDir(t, root)
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

	// A hold folder that cannot be listed holds.
	previous := publishedSessionHoldList
	t.Cleanup(func() { publishedSessionHoldList = previous })
	publishedSessionHoldList = func(string) ([]string, error) { return nil, errors.New("access is denied") }
	if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("a hold folder that cannot be listed must hold: %v", err)
	}

	// An account put an older generation file and its allow back while the
	// folder was held; the lifecycle then bumps and releases right before
	// the hook checks the hold. The hook read the restored generation, so
	// only its second read of the generation refuses the allow.
	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	publishedSessionHoldList = func(dir string) ([]string, error) {
		publishedSessionHoldList = previous
		if err := BumpPublishedSessionGeneration(root); err != nil {
			t.Fatal(err)
		}
		if err := ReleasePublishedSessionRecords(root); err != nil {
			t.Fatal(err)
		}
		return previous(dir)
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

// publishedSessionTestHoldDir creates the hold folder of root (on Windows
// the hook runtime folder next to it, which a test root has not got).
func publishedSessionTestHoldDir(t *testing.T, root string) string {
	t.Helper()
	dir, ok := PublishedSessionHoldDir(root)
	if !ok {
		t.Fatalf("%s has no hold folder", root)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Review P2 (GAP-0352, 1.0.4 loop round 5): a lifecycle run or guardian
// pass never takes over a file at its hold path that it did not make. A
// standard user who could put one there first (the Windows Cisco folder
// under a stock ProgramData access list) could delete it once a repair
// failed, and the hook would trust the old allow again. Whatever is there
// that is not a regular file of this account no one else can change (a
// folder, a link, a file others can write, a file with a second link) is
// replaced by a new hold before the run changes anything.
func TestPublishedSessionHoldReplacesAHoldDefenseClawDidNotMake(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	publishedSessionTestHoldDir(t, root)
	lifecycle, _ := PublishedSessionHoldPath(root)
	removal, ok := PublishedSessionRemovalHoldPath(root, identity)
	if !ok {
		t.Fatal("no removal hold path")
	}
	for _, target := range []struct {
		path string
		hold func() error
	}{
		{lifecycle, func() error { return HoldPublishedSessionRecords(root) }},
		{removal, func() error { return HoldPublishedSessionRemoval(root, identity) }},
	} {
		elsewhere := filepath.Join(t.TempDir(), "kept")
		plants := map[string]func() error{
			"folder": func() error {
				if err := os.Mkdir(target.path, 0o755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(target.path, "x"), nil, 0o644)
			},
			"link": func() error { return os.Symlink(elsewhere, target.path) },
		}
		if runtime.GOOS != "windows" {
			plants["file others can write"] = func() error {
				if err := os.WriteFile(target.path, nil, 0o644); err != nil {
					return err
				}
				return os.Chmod(target.path, 0o666)
			}
			plants["file with a second link"] = func() error {
				if err := os.WriteFile(elsewhere, nil, 0o644); err != nil {
					return err
				}
				return os.Link(elsewhere, target.path)
			}
		}
		for name, plant := range plants {
			if err := plant(); err != nil {
				if name == "link" {
					t.Logf("no link here: %v", err)
					continue
				}
				t.Fatal(err)
			}
			if !PublishedSessionHeld(root) {
				t.Fatalf("%s at %s must hold", name, target.path)
			}
			if err := target.hold(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			info, err := os.Lstat(target.path)
			if err != nil || !info.Mode().IsRegular() || !publishedSessionHoldTrusted(target.path) {
				t.Fatalf("%s at %s must be replaced by a hold DefenseClaw made: %v %v", name, target.path, info, err)
			}
			if data, err := os.ReadFile(target.path); err != nil || !strings.HasPrefix(string(data), publishedSessionHoldText) {
				t.Fatalf("%s: the new hold must explain itself: %q %v", name, data, err)
			}
			if err := RemovePublishedSessionHolds(root); err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(elsewhere)
		}
	}
	// A hold this account made stays the same file.
	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if after, err := os.Lstat(lifecycle); err != nil || !os.SameFile(before, after) {
		t.Fatalf("a hold DefenseClaw made is kept: %v", err)
	}
}

// Review P1/P2 (GAP-0352, 1.0.4 loop round 5): the guardian's hold of one
// account blocks every outage allow, of every account, as the bump it
// stands in for would; it names its account, so a later pass can tell
// whose removal it covers, and releasing it, or the lifecycle's hold, leaves
// the other in place. A hold in the guardian's name that names no account,
// or another account than its name, is reported without one. Uninstall
// removes every hold.
func TestPublishedSessionRemovalHoldNamesItsAccountAndHoldsEveryone(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	publishedSessionTestHoldDir(t, root)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	check := func() error {
		_, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
		return err
	}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatalf("an allow of the current generation proves the process: %v", err)
	}
	other := publishedSessionOtherIdentity(identity)
	if err := HoldPublishedSessionRemoval(root, other); err != nil {
		t.Fatal(err)
	}
	if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) || !strings.Contains(err.Error(), "holds the record folder") {
		t.Fatalf("another account's removal hold must hold this account's allow too: %v", err)
	}
	holds, err := PublishedSessionRemovalHolds(root)
	canonical, _ := connector.CanonicalUserScopedIdentity(other)
	if err != nil || len(holds) != 1 || holds[0].Identity != canonical {
		t.Fatalf("the hold must name its account %q: %+v %v", canonical, holds, err)
	}
	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if err := ReleasePublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
		t.Fatalf("the lifecycle's release must leave the guardian's hold: %v", err)
	}
	if err := ReleasePublishedSessionRemoval(root, other); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatalf("after the release the allow proves the process: %v", err)
	}

	// A file in the guardian's name that names another account, or none.
	path, _ := PublishedSessionRemovalHoldPath(root, other)
	for _, text := range []string{publishedSessionHoldText + "account " + identity + "\n", "", "account nobody\n"} {
		if err := createPublishedSessionHold(path, text); err != nil {
			t.Fatal(err)
		}
		holds, err := PublishedSessionRemovalHolds(root)
		if err != nil || len(holds) != 1 || holds[0].Identity != "" {
			t.Fatalf("a hold that does not name the account of its name names none (%q): %+v %v", text, holds, err)
		}
		if err := check(); !errors.Is(err, ErrPublishedSessionUnavailable) {
			t.Fatalf("it still holds: %v", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}

	if err := HoldPublishedSessionRemoval(root, identity); err != nil {
		t.Fatal(err)
	}
	if err := HoldPublishedSessionRecords(root); err != nil {
		t.Fatal(err)
	}
	if err := RemovePublishedSessionHolds(root); err != nil || PublishedSessionHeld(root) {
		t.Fatalf("uninstall removes every hold: %v", err)
	}
	// No hold folder holds nothing: the hook then has no summary (Windows)
	// or no record folder (Linux, macOS) to prove an allow with.
	previous := publishedSessionHoldList
	t.Cleanup(func() { publishedSessionHoldList = previous })
	publishedSessionHoldList = func(string) ([]string, error) { return nil, fs.ErrNotExist }
	if PublishedSessionHeld(root) {
		t.Fatal("a missing hold folder holds nothing")
	}
}
