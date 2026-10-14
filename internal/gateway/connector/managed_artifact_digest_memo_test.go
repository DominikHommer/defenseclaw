// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// useManagedArtifactDigestSeams replaces the per-OS memo seams and the memo
// clock for one test, and empties the memo before and after it. ends counts
// the change epochs the digest ended (one per full read of a guarded file).
func useManagedArtifactDigestSeams(
	t *testing.T,
	stamp func(*os.File) (managedArtifactStamp, bool),
	exclusive func(string) (*os.File, error),
	end func(*os.File) error,
) (clock *time.Time, ends *int) {
	t.Helper()
	savedEligible, savedStamp, savedOpen, savedEnd, savedNow := managedArtifactDigestMemoEligible,
		managedArtifactStampOf, openManagedArtifactExclusive, endManagedArtifactChangeEpoch, managedArtifactDigests.now
	now := time.Unix(1_800_000_000, 0)
	count := 0
	managedArtifactStampOf, openManagedArtifactExclusive = stamp, exclusive
	endManagedArtifactChangeEpoch = func(file *os.File) error {
		count++
		return end(file)
	}
	managedArtifactDigests.Lock()
	managedArtifactDigests.entries = nil
	managedArtifactDigests.now = func() time.Time { return now }
	managedArtifactDigests.Unlock()
	t.Cleanup(func() {
		managedArtifactDigestMemoEligible, managedArtifactStampOf = savedEligible, savedStamp
		openManagedArtifactExclusive, endManagedArtifactChangeEpoch = savedOpen, savedEnd
		managedArtifactDigests.Lock()
		managedArtifactDigests.entries = nil
		managedArtifactDigests.now = savedNow
		managedArtifactDigests.Unlock()
	})
	return &now, &count
}

func endManagedArtifactChangeEpochFake(*os.File) error { return nil }

func writeManagedArtifactFixture(t *testing.T, path string, fill byte) string {
	t.Helper()
	body := bytes.Repeat([]byte{fill}, 2<<20)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func managedArtifactDigestOf(t *testing.T, path string, memoize bool) string {
	t.Helper()
	got, exists, err := stableManagedArtifactDigestWith(path, "managed hook runtime artifact", 4<<20, "", memoize)
	if err != nil || !exists {
		t.Fatalf("digest %s: %v, exists %v", path, err, exists)
	}
	return got
}

func managedArtifactDigestRemembered(path string) bool {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	_, ok := managedArtifactDigests.entries[managedArtifactDigestKey(path)]
	return ok
}

func managedArtifactDigestEntries() int {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	return len(managedArtifactDigests.entries)
}

// GAP-0438: the guardian's interval reconcile digests the enterprise hook
// binary for every Claude Code, Codex and Cursor target. The binary is read
// again only when the version stamp of the opened file changes or its last
// full read is 10 minutes old. Each full read first ends the change epoch of
// the file; a memo hit never does.
func TestManagedArtifactDigestReadsTheHookBinaryOnlyWhenItsVersionChanges(t *testing.T) {
	version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
	clock, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return version, true },
		os.Open,
		endManagedArtifactChangeEpochFake,
	)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	first := writeManagedArtifactFixture(t, path, 1)
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("first digest %s, want %s", got, first)
	}
	if *ends != 1 {
		t.Fatalf("the full read ended %d change epochs, want 1", *ends)
	}
	// The fake stamp does not follow this write, so the old digest proves
	// the unchanged version was not read again.
	second := writeManagedArtifactFixture(t, path, 2)
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("an unchanged version was read again: %s, want %s", got, first)
	}
	if *ends != 1 {
		t.Fatalf("a memo hit ended the change epoch (%d ends)", *ends)
	}
	version.USN = 11
	if got := managedArtifactDigestOf(t, path, true); got != second {
		t.Fatalf("a new version kept the old digest: %s, want %s", got, second)
	}
	if *ends != 2 {
		t.Fatalf("the full read of a new version ended %d change epochs in all, want 2", *ends)
	}
	// The bound is the literal 10 minutes of the guardian's own hook binary
	// check, not the constant under test.
	third := writeManagedArtifactFixture(t, path, 3)
	*clock = clock.Add(10*time.Minute - time.Second)
	if got := managedArtifactDigestOf(t, path, true); got != second {
		t.Fatalf("the memo ended before 10 minutes: %s, want %s", got, second)
	}
	*clock = clock.Add(time.Second)
	if got := managedArtifactDigestOf(t, path, true); got != third {
		t.Fatalf("the memo outlived 10 minutes: %s, want %s", got, third)
	}
}

func TestManagedArtifactDigestMemoizesNothingWithoutAGuardedStableStamp(t *testing.T) {
	cases := []struct {
		name      string
		memoize   bool
		stamp     func(*os.File) (managedArtifactStamp, bool)
		exclusive func(string) (*os.File, error)
		end       func(*os.File) error
		wantEnds  int
	}{
		{
			name:      "not an eligible artifact",
			memoize:   false,
			stamp:     func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
			exclusive: os.Open,
			end:       endManagedArtifactChangeEpochFake,
			wantEnds:  0,
		},
		{
			name:    "a writer holds the file",
			memoize: true,
			stamp:   func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
			exclusive: func(string) (*os.File, error) {
				return nil, os.ErrPermission
			},
			end:      endManagedArtifactChangeEpochFake,
			wantEnds: 0,
		},
		{
			name:      "no change journal",
			memoize:   true,
			stamp:     func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{}, false },
			exclusive: os.Open,
			end:       endManagedArtifactChangeEpochFake,
			wantEnds:  3,
		},
		{
			name:      "the change epoch cannot be ended",
			memoize:   true,
			stamp:     func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
			exclusive: os.Open,
			end:       func(*os.File) error { return errors.ErrUnsupported },
			wantEnds:  3,
		},
		{
			name:    "the stamp moved during the read",
			memoize: true,
			stamp: func() func(*os.File) (managedArtifactStamp, bool) {
				usn := int64(0)
				return func(*os.File) (managedArtifactStamp, bool) {
					usn++
					return managedArtifactStamp{ID: 1, USN: usn}, true
				}
			}(),
			exclusive: os.Open,
			end:       endManagedArtifactChangeEpochFake,
			wantEnds:  3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ends := useManagedArtifactDigestSeams(t, tc.stamp, tc.exclusive, tc.end)
			path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
			for fill := byte(1); fill <= 3; fill++ {
				want := writeManagedArtifactFixture(t, path, fill)
				if got := managedArtifactDigestOf(t, path, tc.memoize); got != want {
					t.Fatalf("version %d: digest %s, want %s (memoized)", fill, got, want)
				}
			}
			if left := managedArtifactDigestEntries(); left != 0 {
				t.Fatalf("%d memo entries kept", left)
			}
			if *ends != tc.wantEnds {
				t.Fatalf("%d change epochs ended, want %d", *ends, tc.wantEnds)
			}
		})
	}
}

// A full read that remembers nothing also drops the digest remembered for an
// earlier version, so no later call can answer from it.
func TestManagedArtifactDigestFullReadDropsTheRememberedDigest(t *testing.T) {
	cases := []struct {
		name    string
		moving  bool // the stamp moves on every call: the read is not remembered
		failEnd bool // a new version whose change epoch cannot be ended
	}{
		{name: "the stamp moved during the read", moving: true},
		{name: "the change epoch cannot be ended", failEnd: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
			moving, failEnd := false, false
			useManagedArtifactDigestSeams(t,
				func(*os.File) (managedArtifactStamp, bool) {
					if moving {
						version.USN++
					}
					return version, true
				},
				os.Open,
				func(*os.File) error {
					if failEnd {
						return errors.ErrUnsupported
					}
					return nil
				},
			)
			path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
			writeManagedArtifactFixture(t, path, 1)
			managedArtifactDigestOf(t, path, true)
			if !managedArtifactDigestRemembered(path) {
				t.Fatal("the first full read was not remembered")
			}
			moving = tc.moving
			if tc.failEnd {
				version.USN++
				failEnd = true
			}
			want := writeManagedArtifactFixture(t, path, 2)
			if got := managedArtifactDigestOf(t, path, true); got != want {
				t.Fatalf("digest %s, want the full read %s", got, want)
			}
			if managedArtifactDigestRemembered(path) {
				t.Fatal("a full read that remembered nothing kept the earlier digest")
			}
		})
	}
}

// A memo hit also needs the path to still name the opened file: a rename
// after the open turns the call into a full read, which reports the change
// and drops the remembered digest.
func TestManagedArtifactDigestMemoMissesWhenThePathIsReplacedAfterTheOpen(t *testing.T) {
	// os.Open on Windows shares no delete access, so the open file can be
	// renamed there only through the deny-write open of the product.
	open := os.Open
	if runtime.GOOS == "windows" {
		open = openManagedArtifactExclusive
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "defenseclaw-hook.exe")
	replacement := filepath.Join(dir, "defenseclaw-hook.exe.new")
	version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
	replace := false
	useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) {
			// The first stamp of a call comes after the open and its
			// identity checks, right before the memo lookup.
			if replace {
				replace = false
				if err := os.Rename(path, path+".old"); err != nil {
					t.Errorf("move the opened file away: %v", err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Errorf("rename the replacement in: %v", err)
				}
			}
			return version, true
		},
		open,
		endManagedArtifactChangeEpochFake,
	)
	first := writeManagedArtifactFixture(t, path, 1)
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("first digest %s, want %s", got, first)
	}
	writeManagedArtifactFixture(t, replacement, 2)
	replace = true
	got, exists, err := stableManagedArtifactDigestWith(path, "managed hook runtime artifact", 4<<20, "", true)
	if replace {
		t.Fatal("the call took no stamp")
	}
	if err == nil || got == first || !exists {
		t.Fatalf("a path replaced after the open: digest %q, exists %v, err %v; want the change reported", got, exists, err)
	}
	if managedArtifactDigestRemembered(path) {
		t.Fatal("the remembered digest outlived a replacement of the path")
	}
}

// memoArtifactConnector lists fixed hook runtime artifacts.
type memoArtifactConnector struct {
	stubConnector
	artifacts []string
}

func (c *memoArtifactConnector) HookRuntimeArtifacts(SetupOpts) []string { return c.artifacts }

// GAP-0438 at the production call site: managedHookScriptDigests memoizes an
// eligible hook binary outside the connector data dir and reads a file of the
// data dir in full on every call, eligible or not.
func TestManagedHookScriptDigestsMemoizesOnlyTheHookBinaryOutsideTheDataDir(t *testing.T) {
	version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
	_, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return version, true },
		os.Open,
		endManagedArtifactChangeEpochFake,
	)
	managedArtifactDigestMemoEligible = func(string) bool { return true }
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	script := filepath.Join(dataDir, "hooks", "inspect-tool.sh")
	conn := &memoArtifactConnector{stubConnector: stubConnector{name: "memo-artifacts"}, artifacts: []string{binary, script}}
	opts := SetupOpts{DataDir: dataDir}

	binaryFirst := writeManagedArtifactFixture(t, binary, 1)
	scriptFirst := writeManagedArtifactFixture(t, script, 2)
	got, err := managedHookScriptDigests(opts, conn)
	if err != nil {
		t.Fatal(err)
	}
	if got[filepath.Base(binary)] != binaryFirst || got[filepath.Base(script)] != scriptFirst {
		t.Fatalf("first digests %v, want %s and %s", got, binaryFirst, scriptFirst)
	}
	// The fake stamp does not follow these writes: the hook binary keeps
	// its first digest (one full read across both calls) and the data-dir
	// script gets its new one (a full read on every call).
	writeManagedArtifactFixture(t, binary, 3)
	scriptSecond := writeManagedArtifactFixture(t, script, 4)
	got, err = managedHookScriptDigests(opts, conn)
	if err != nil {
		t.Fatal(err)
	}
	if got[filepath.Base(binary)] != binaryFirst {
		t.Fatalf("the hook binary outside the data dir was read again: %s, want %s", got[filepath.Base(binary)], binaryFirst)
	}
	if got[filepath.Base(script)] != scriptSecond {
		t.Fatalf("a data-dir file was memoized: %s, want %s", got[filepath.Base(script)], scriptSecond)
	}
	if *ends != 1 {
		t.Fatalf("%d full memo reads across two calls, want 1", *ends)
	}
	if managedArtifactDigestRemembered(script) {
		t.Fatal("a data-dir file has a memo entry")
	}
}

// VerifyManagedSharedHookScriptDigests, and every other caller of
// stableManagedArtifactDigestForOwner, reads the file in full on every call.
func TestStableManagedArtifactDigestForOwnerNeverMemoizes(t *testing.T) {
	_, ends := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
		os.Open,
		endManagedArtifactChangeEpochFake,
	)
	managedArtifactDigestMemoEligible = func(string) bool { return true }
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	for fill := byte(1); fill <= 3; fill++ {
		want := writeManagedArtifactFixture(t, path, fill)
		got, exists, err := stableManagedArtifactDigestForOwner(path, "managed shared hook script", 4<<20, "")
		if err != nil || !exists || got != want {
			t.Fatalf("version %d: digest %s, exists %v, err %v; want %s", fill, got, exists, err, want)
		}
	}
	if left := managedArtifactDigestEntries(); left != 0 || *ends != 0 {
		t.Fatalf("stableManagedArtifactDigestForOwner memoized: %d entries, %d change epochs ended", left, *ends)
	}
}

// Only the enterprise hook binary outside the connector data dir may be
// memoized: a hook script or token sidecar in the per-user data dir is read
// in full on every call.
func TestManagedArtifactDigestMemoSkipsTheConnectorDataDir(t *testing.T) {
	saved := managedArtifactDigestMemoEligible
	t.Cleanup(func() { managedArtifactDigestMemoEligible = saved })
	dataDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "bin", "defenseclaw-hook.exe")
	inside := filepath.Join(dataDir, "hooks", "defenseclaw-hook.exe")

	managedArtifactDigestMemoEligible = func(string) bool { return true }
	if !managedArtifactDigestMemoWanted(dataDir, outside) {
		t.Fatal("the eligible hook binary outside the data dir is not memoized")
	}
	if managedArtifactDigestMemoWanted(dataDir, inside) {
		t.Fatal("a file in the connector data dir is memoized")
	}
	managedArtifactDigestMemoEligible = func(string) bool { return false }
	if managedArtifactDigestMemoWanted(dataDir, outside) {
		t.Fatal("an artifact that is not the enterprise hook binary is memoized")
	}
}
