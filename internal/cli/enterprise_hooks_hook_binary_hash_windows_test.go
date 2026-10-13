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

// countWindowsHookFileReads makes the guardian record of the hook binary
// fresh for the test and counts the full reads of each existing file.
func countWindowsHookFileReads(t *testing.T) map[string]int {
	t.Helper()
	reads := map[string]int{}
	saved := windowsHookFileHashes
	windowsHookFileHashes = &hookFileHashCache{
		stamp: windowsHookFileStampOf,
		hash: func(path string) (string, error) {
			sum, err := windowsFileSHA256Hex(path)
			if err == nil {
				reads[strings.ToLower(filepath.Clean(path))]++
			}
			return sum, err
		},
		now:    time.Now,
		maxAge: windowsHookBinaryRehashInterval,
	}
	t.Cleanup(func() { windowsHookFileHashes = saved })
	return reads
}

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

// GAP-0401: an unchanged hook binary and its protected copy are read once,
// not at every check and before every reconcile.
func TestKeepWindowsManagedFileCopyReadsAnUnchangedBinaryOnce(t *testing.T) {
	reads := countWindowsHookFileReads(t)
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release")
	for i := range 6 {
		refresh := i%2 == 0 // the reconcile refreshes the copy, the 5 s check does not
		if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, refresh); err != nil || damage != "" {
			t.Fatalf("check %d: restored %q, %v", i, damage, err)
		}
	}
	key := func(path string) string { return strings.ToLower(filepath.Clean(path)) }
	if reads[key(target)] != 1 {
		t.Fatalf("the unchanged hook binary was read %d times, want 1", reads[key(target)])
	}
	// The first refresh creates the copy; the next one reads it once.
	if reads[key(copyPath)] != 1 {
		t.Fatalf("the unchanged protected copy was read %d times, want 1", reads[key(copyPath)])
	}
}

// GAP-0401: the cheap check keeps the tamper guarantee. A binary replaced in
// place or by a rename with one of the same size, whose last-write time was
// set back, is found at the next check and restored.
func TestKeepWindowsManagedFileCopyFindsASameSizeReplacement(t *testing.T) {
	countWindowsHookFileReads(t)
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

// GAP-0401: a time stamp change alone reads the binary again, reports no
// damage and is not read again after that.
func TestKeepWindowsManagedFileCopyHandlesATimeStampOnlyChange(t *testing.T) {
	reads := countWindowsHookFileReads(t)
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release")
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	key := strings.ToLower(filepath.Clean(target))
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(target, later, later); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
			t.Fatalf("time stamp change: restored %q, %v", damage, err)
		}
	}
	if reads[key] != 2 {
		t.Fatalf("the binary was read %d times, want 2 (once more after the time stamp change)", reads[key])
	}
}

// The stamp names the file version: equal for the same file, different
// after a write, and taken without opening the file data.
func TestWindowsHookFileStampFollowsTheFileVersion(t *testing.T) {
	target, _, _ := writeWindowsHookBinaryFixture(t, "hook release")
	first, err := windowsHookFileStampOf(target)
	if err != nil {
		t.Fatal(err)
	}
	again, err := windowsHookFileStampOf(target)
	if err != nil || again != first {
		t.Fatalf("stamp of an unchanged file changed: %+v, %+v, %v", first, again, err)
	}
	if first.ID == 0 || first.Size != int64(len("hook release")) || first.Links != 1 {
		t.Fatalf("stamp = %+v", first)
	}
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(target, []byte("hook releasf"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := windowsHookFileStampOf(target)
	if err != nil || after == first {
		t.Fatalf("stamp did not change after a write: %+v, %v", after, err)
	}
	// A handle that shares only reading does not stop the stamp: it opens
	// attributes only.
	name, _ := windows.UTF16PtrFromString(target)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if _, err := windowsHookFileStampOf(target); err != nil {
		t.Fatalf("stamp while the binary is open for read: %v", err)
	}
}
