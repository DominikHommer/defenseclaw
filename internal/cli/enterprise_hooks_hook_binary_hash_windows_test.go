//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func writeWindowsHookBinaryFixture(t *testing.T, body string) (target, copyPath, want string) {
	t.Helper()
	root := t.TempDir()
	target = filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath = filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	return target, copyPath, want
}

func TestKeepWindowsManagedFileCopyUsesSharedTargetHash(t *testing.T) {
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release")
	saved := guardianTargetHookSHA256Hex
	calls := 0
	guardianTargetHookSHA256Hex = func(path string) (string, error) {
		if path != target {
			t.Errorf("target hash path %q, want %q", path, target)
		}
		calls++
		return saved(path)
	}
	t.Cleanup(func() { guardianTargetHookSHA256Hex = saved })
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
		t.Fatalf("healthy target: damage %q, err %v", damage, err)
	}
	if calls != 1 {
		t.Fatalf("guardian used the shared target hash %d times, want once", calls)
	}
}

// The guardian leaves a healthy protected copy in place through repeated
// five-second checks and reconciles. Portable connector tests count data
// reads by both callers of the shared digest memo.
func TestKeepWindowsManagedFileCopyKeepsAnUnchangedCopy(t *testing.T) {
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release")
	var first os.FileInfo
	for i := range 6 {
		refresh := i%2 == 0 // the reconcile refreshes the copy, the 5 s check does not
		if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, refresh); err != nil || damage != "" {
			t.Fatalf("check %d: restored %q, %v", i, damage, err)
		}
		current, err := os.Stat(copyPath)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = current
		} else if !os.SameFile(first, current) {
			t.Fatal("a healthy protected copy was replaced")
		}
	}
}

// GAP-0401: the cheap check keeps the tamper guarantee. A binary replaced in
// place or by a rename with one of the same size, whose last-write time was
// set back, is found at the next check and restored.
func TestKeepWindowsManagedFileCopyFindsASameSizeReplacement(t *testing.T) {
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release A")
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
		t.Fatalf("healthy binary: restored %q, %v", damage, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	written := info.ModTime()

	for _, c := range []struct {
		name    string
		replace func() error
	}{
		{"in place", func() error { return os.WriteFile(target, []byte("hook release B"), 0o600) }},
		{"by rename", func() error {
			other := target + ".other"
			if err := os.WriteFile(other, []byte("hook release C"), 0o600); err != nil {
				return err
			}
			if err := os.Chtimes(other, written, written); err != nil {
				return err
			}
			from, _ := windows.UTF16PtrFromString(other)
			to, _ := windows.UTF16PtrFromString(target)
			return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING)
		}},
	} {
		// File times have the resolution of the system clock.
		time.Sleep(50 * time.Millisecond)
		if err := c.replace(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(target, written, written); err != nil {
			t.Fatal(err)
		}
		if replaced, err := os.Stat(target); err != nil || replaced.Size() != info.Size() || !replaced.ModTime().Equal(written) {
			t.Fatalf("%s: fixture is not a same-size, same-time replacement: %v", c.name, err)
		}
		damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
		if err != nil || !strings.Contains(damage, "hash mismatch") {
			t.Fatalf("%s: the replacement was not found: restored %q, %v", c.name, damage, err)
		}
		if body, err := os.ReadFile(target); err != nil || string(body) != "hook release A" {
			t.Fatalf("%s: restored %q, %v", c.name, body, err)
		}
	}
}

// A time stamp change alone reports no damage and keeps the copy in place.
func TestKeepWindowsManagedFileCopyHandlesATimeStampOnlyChange(t *testing.T) {
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release")
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	before, err := os.Stat(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(target, later, later); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
			t.Fatalf("time stamp change: restored %q, %v", damage, err)
		}
	}
	after, err := os.Stat(copyPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the time change replaced the protected copy: %v", err)
	}
}

// A stale copy memo must never authorize a restore. The restore branch reads
// the source afresh before copying and leaves a missing target missing when
// the protected copy has been damaged.
func TestKeepWindowsManagedFileCopyChecksProtectedCopyBeforeRestore(t *testing.T) {
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release A")
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	saved := guardianCopyHookSHA256Hex
	guardianCopyHookSHA256Hex = func(string) (string, error) { return want, nil }
	t.Cleanup(func() { guardianCopyHookSHA256Hex = saved })
	if err := os.WriteFile(copyPath, []byte("hook release B"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err == nil || damage != "" {
		t.Fatalf("damaged copy restored the target: damage %q, err %v", damage, err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("a damaged protected copy created a target: %v", err)
	}
}
