// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// useManagedArtifactDigestSeams replaces the per-OS memo seams and the memo
// clock for one test, and empties the memo before and after it.
func useManagedArtifactDigestSeams(
	t *testing.T,
	stamp func(*os.File) (managedArtifactStamp, bool),
	exclusive func(string) (*os.File, error),
) *time.Time {
	t.Helper()
	savedStamp, savedOpen, savedNow := managedArtifactStampOf, openManagedArtifactExclusive, managedArtifactDigests.now
	clock := time.Unix(1_800_000_000, 0)
	managedArtifactStampOf, openManagedArtifactExclusive = stamp, exclusive
	managedArtifactDigests.Lock()
	managedArtifactDigests.entries = nil
	managedArtifactDigests.now = func() time.Time { return clock }
	managedArtifactDigests.Unlock()
	t.Cleanup(func() {
		managedArtifactStampOf, openManagedArtifactExclusive = savedStamp, savedOpen
		managedArtifactDigests.Lock()
		managedArtifactDigests.entries = nil
		managedArtifactDigests.now = savedNow
		managedArtifactDigests.Unlock()
	})
	return &clock
}

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

// GAP-0438: the guardian's interval reconcile digests the enterprise hook
// binary for every Claude Code, Codex and Cursor target. The binary is read
// again only when the version stamp of the opened file changes or its last
// full read is managedArtifactDigestMaxAge old.
func TestManagedArtifactDigestReadsTheHookBinaryOnlyWhenItsVersionChanges(t *testing.T) {
	version := managedArtifactStamp{Volume: 7, ID: 1, Size: 2 << 20, USN: 10}
	clock := useManagedArtifactDigestSeams(t,
		func(*os.File) (managedArtifactStamp, bool) { return version, true },
		os.Open,
	)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	first := writeManagedArtifactFixture(t, path, 1)
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("first digest %s, want %s", got, first)
	}
	// The fake stamp does not follow this write, so the old digest proves
	// the unchanged version was not read again.
	second := writeManagedArtifactFixture(t, path, 2)
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("an unchanged version was read again: %s, want %s", got, first)
	}
	version.USN = 11
	if got := managedArtifactDigestOf(t, path, true); got != second {
		t.Fatalf("a new version kept the old digest: %s, want %s", got, second)
	}
	third := writeManagedArtifactFixture(t, path, 3)
	*clock = clock.Add(managedArtifactDigestMaxAge - time.Second)
	if got := managedArtifactDigestOf(t, path, true); got != second {
		t.Fatalf("the memo ended before its age: %s, want %s", got, second)
	}
	*clock = clock.Add(time.Second)
	if got := managedArtifactDigestOf(t, path, true); got != third {
		t.Fatalf("the memo outlived %s: %s, want %s", managedArtifactDigestMaxAge, got, third)
	}
}

func TestManagedArtifactDigestMemoizesNothingWithoutAGuardedStableStamp(t *testing.T) {
	cases := []struct {
		name      string
		memoize   bool
		stamp     func(*os.File) (managedArtifactStamp, bool)
		exclusive func(string) (*os.File, error)
	}{
		{
			name:      "not an eligible artifact",
			memoize:   false,
			stamp:     func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
			exclusive: os.Open,
		},
		{
			name:    "a writer holds the file",
			memoize: true,
			stamp:   func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{ID: 1, USN: 1}, true },
			exclusive: func(string) (*os.File, error) {
				return nil, os.ErrPermission
			},
		},
		{
			name:      "no change journal",
			memoize:   true,
			stamp:     func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{}, false },
			exclusive: os.Open,
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
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useManagedArtifactDigestSeams(t, tc.stamp, tc.exclusive)
			path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
			for fill := byte(1); fill <= 3; fill++ {
				want := writeManagedArtifactFixture(t, path, fill)
				if got := managedArtifactDigestOf(t, path, tc.memoize); got != want {
					t.Fatalf("version %d: digest %s, want %s (memoized)", fill, got, want)
				}
			}
			managedArtifactDigests.Lock()
			left := len(managedArtifactDigests.entries)
			managedArtifactDigests.Unlock()
			if left != 0 {
				t.Fatalf("%d memo entries kept", left)
			}
		})
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
