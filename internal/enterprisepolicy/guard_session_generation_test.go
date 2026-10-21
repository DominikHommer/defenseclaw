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
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// publishedSessionTestRoot is a record folder with a generation file, as the
// lifecycle makes it, owned by the test account.
func publishedSessionTestRoot(t *testing.T) string {
	t.Helper()
	withoutPublishedSessionACL(t)
	withPublishedSessionGenerationOfTheTestAccount(t)
	root := t.TempDir()
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	return root
}

// withPublishedSessionGenerationOfTheTestAccount accepts a generation file
// the test account owns where the gateway accepts only root's.
func withPublishedSessionGenerationOfTheTestAccount(t *testing.T) {
	t.Helper()
	previous := publishedSessionGenerationOwner
	publishedSessionGenerationOwner = func(path string, info os.FileInfo, _ bool) error {
		return checkPublishedSessionGenerationOwner(path, info, true)
	}
	t.Cleanup(func() { publishedSessionGenerationOwner = previous })
}

// publishCurrent publishes an answer the way the gateway does: stamped with
// the generation it reads first ("" when it cannot read one).
func publishCurrent(root, identity string, key SessionKey, decision GuardDecision, now time.Time) error {
	generation, _ := PublishedSessionGeneration(root)
	return PublishForeignHookSessionDecision(root, identity, key, decision, generation, now)
}

func publishedSessionTestGeneration(t *testing.T, root string) int64 {
	t.Helper()
	generation, err := PublishedSessionGeneration(root)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.ParseInt(generation, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// Lead directive (GAP-0352 review loop round 1): an outage allow is honored
// only when its record carries the record folder's current generation. A
// bump (the lifecycle's, the guardian's) ends every allow written before
// it, of every connector and account, with no record found or deleted; the
// next exchange's allow proves the process again. An allow stamped with the
// generation the gateway read before the bump, or with none, proves
// nothing. A block of an earlier generation still denies. A generation file
// that is missing, refused by the trust check, not a regular file, or not
// owned the way the gateway requires blocks.
func TestPublishedSessionGenerationEndsEveryEarlierAllow(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	other := SessionKey{Connector: "opencode", Session: "o-1", Process: "p-2"}
	check := func(k SessionKey, trust func(string) error) (GuardDecision, error) {
		t.Helper()
		return CheckPublishedForeignHookSession(root, identity, k, GuardDecision{}, trust)
	}
	proves := func(step string, k SessionKey) {
		t.Helper()
		if got, err := check(k, trustAll); err != nil || got.Deny {
			t.Fatalf("%s: the allow must prove the process: %+v %v", step, got, err)
		}
	}
	refuses := func(step string, k SessionKey, trust func(string) error) {
		t.Helper()
		if got, err := check(k, trust); !errors.Is(err, ErrPublishedSessionUnavailable) || got.Deny {
			t.Fatalf("%s: the allow must prove nothing: %+v %v", step, got, err)
		}
	}
	allow := func(k SessionKey) {
		t.Helper()
		if err := publishCurrent(root, identity, k, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	allow(key)
	allow(other)
	proves("current generation", key)
	proves("current generation, another connector", other)

	first := publishedSessionTestGeneration(t, root)
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if second := publishedSessionTestGeneration(t, root); second <= first {
		t.Fatalf("a bump must move the generation forward: %d after %d", second, first)
	}
	refuses("after a bump", key, trustAll)
	refuses("after a bump, another connector", other, trustAll)
	if _, err := check(key, trustAll); err == nil || !strings.Contains(err.Error(), "earlier generation") {
		t.Fatalf("the refusal must name the generation: %v", err)
	}
	allow(key)
	proves("the next exchange's allow", key)
	refuses("a record no exchange wrote again", other, trustAll)

	// The gateway read the generation, the guardian then recorded a removal
	// and bumped, and the gateway published its answer from the old ledger.
	stale, err := PublishedSessionGeneration(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, stale, time.Now()); err != nil {
		t.Fatal(err)
	}
	refuses("an allow stamped with the generation read before the bump", key, trustAll)
	if err := PublishForeignHookSessionDecision(root, identity, key, GuardDecision{}, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	refuses("an allow without a generation", key, trustAll)

	// A block denies whatever its generation.
	reason := foreignHookBlockedPrefix + " the project hook /repo/.github/hooks/x.json"
	if err := publishCurrent(root, identity, key, GuardDecision{Deny: true, Reason: reason}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if got, err := check(key, trustAll); err != nil || !got.Deny || got.Reason != reason {
		t.Fatalf("a block of an earlier generation must still deny: %+v %v", got, err)
	}

	generationPath, ok := PublishedSessionGenerationPath(root)
	if !ok {
		t.Fatal("no generation path")
	}
	allow(key)
	proves("before the generation file changes", key)
	refuses("a generation file the trust check refuses", key, func(path string) error {
		if path == generationPath {
			return errors.New("writable by the user")
		}
		return nil
	})
	if err := os.Remove(generationPath); err != nil {
		t.Fatal(err)
	}
	refuses("no generation file", key, trustAll)
	if _, err := PublishedSessionGeneration(root); err == nil {
		t.Fatal("the gateway reads no generation from a missing file")
	}
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	refuses("a generation file created again", key, trustAll)
	allow(key)
	proves("the allow after the new generation file", key)

	if err := os.Remove(generationPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(generationPath, 0o755); err != nil {
		t.Fatal(err)
	}
	refuses("a folder at the generation path", key, trustAll)
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(generationPath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("the bump must replace what is not a generation file: %v %v", info, err)
	}
	refuses("the allow from before the replacement", key, trustAll)

	// A generation file the gateway does not trust gives no generation, so
	// the answers it publishes prove nothing.
	previous := publishedSessionGenerationOwner
	publishedSessionGenerationOwner = func(path string, _ os.FileInfo, _ bool) error {
		return errors.New(path + " is owned by another account")
	}
	if _, err := PublishedSessionGeneration(root); err == nil {
		t.Fatal("the gateway must refuse a generation file of another owner")
	}
	allow(key)
	publishedSessionGenerationOwner = previous
	refuses("an allow published while the generation file was refused", key, trustAll)
}

// A bump only ever moves the generation forward and fails closed: a
// generation file dated ahead (a clock set back) gets a later time still; a
// file system that keeps whole seconds gets the next second; a time that
// cannot be set removes the file, so every outage allow blocks until the
// next bump; and only a bump that could do neither is an error. The record
// folder must exist: one that is missing may come back with its own old
// generation file. A link planted at the generation path is replaced, and
// its target is not touched.
func TestBumpPublishedSessionGenerationOnlyMovesForwardAndFailsClosed(t *testing.T) {
	root := publishedSessionTestRoot(t)
	path, _ := PublishedSessionGenerationPath(root)
	ahead := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, ahead, ahead); err != nil {
		t.Fatal(err)
	}
	before := publishedSessionTestGeneration(t, root)
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if after := publishedSessionTestGeneration(t, root); after <= before {
		t.Fatalf("a generation dated ahead must still move forward: %d after %d", after, before)
	}

	// Whole seconds: the first time does not take.
	whole := time.Now().Add(10 * time.Second).Truncate(time.Second)
	if err := os.Chtimes(path, whole, whole); err != nil {
		t.Fatal(err)
	}
	previousSet := publishedSessionSetTime
	t.Cleanup(func() { publishedSessionSetTime = previousSet })
	publishedSessionSetTime = func(name string, at time.Time) error { return previousSet(name, at.Truncate(time.Second)) }
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if after := publishedSessionTestGeneration(t, root); after != whole.Add(time.Second).UnixNano() {
		t.Fatalf("a file system that keeps whole seconds must get the next second: %d, want %d", after, whole.Add(time.Second).UnixNano())
	}

	// The time cannot be set: the file goes.
	publishedSessionSetTime = func(string, time.Time) error { return errors.New("the volume is read-only") }
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatalf("a bump that removed the generation is closed, not an error: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("a generation that cannot move must be removed: %v", err)
	}
	// Neither the time nor the removal: an error.
	publishedSessionSetTime = previousSet
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	publishedSessionSetTime = func(string, time.Time) error { return errors.New("the volume is read-only") }
	previousRemove := publishedSessionRemove
	t.Cleanup(func() { publishedSessionRemove = previousRemove })
	publishedSessionRemove = func(name string) error {
		if name == path {
			return errors.New("the volume is read-only")
		}
		return previousRemove(name)
	}
	if err := BumpPublishedSessionGeneration(root); err == nil {
		t.Fatal("a bump that changed nothing must report it")
	}
	publishedSessionSetTime, publishedSessionRemove = previousSet, previousRemove

	for name, folder := range map[string]string{
		"missing":   filepath.Join(t.TempDir(), "missing"),
		"a file":    path,
		"relative":  "sessions",
		"no folder": "",
	} {
		if err := BumpPublishedSessionGeneration(folder); err == nil {
			t.Fatalf("%s record folder: the bump must fail", name)
		}
	}

	if runtime.GOOS == "windows" {
		return
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(target, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("a link at the generation path must be replaced: %v %v", info, err)
	}
	if info, err := os.Stat(target); err != nil || !info.ModTime().Equal(old) {
		t.Fatalf("the link's target must not be touched: %v %v", info, err)
	}
}
