// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// On a managed Windows host the hook runtime of every enrolled Claude Code,
// Codex and Cursor target includes the 128 MB defenseclaw-hook.exe, and the
// stable digest reads a file twice. The guardian verifies each target on
// every interval reconcile, so an idle device read about 517 MB a minute of
// that one unchanged file, and 2 GB a minute with agents in use (GAP-0438).
// The administrator-owned enterprise hook binary is now read again only
// when the version of the opened file changed, or when its last full read
// is managedArtifactDigestMaxAge old. Every call still opens the file and
// checks its identity, link count and reparse attributes; the guardian's
// 5-second check of the hook binary is unchanged.

// managedArtifactDigestMaxAge is the longest an unchanged artifact goes
// without a full read: the same bound as the guardian's own hook binary
// check (windowsHookBinaryRehashInterval in internal/cli).
const managedArtifactDigestMaxAge = 10 * time.Minute

// managedArtifactStamp is what the file system reports about one version of
// an open file without reading its data: volume, file id, size, link count,
// last-write and change times, attributes and change-journal number.
type managedArtifactStamp struct {
	Volume     uint32
	ID         uint64
	Size       int64
	Links      uint32
	Written    int64
	Changed    int64
	USN        int64
	Attributes uint32
}

type managedArtifactDigestEntry struct {
	stamp  managedArtifactStamp
	digest string
	at     time.Time
}

// managedArtifactDigests is the digest of each memoized artifact with the
// stamp it had when it was read in full. now is replaced in tests.
var managedArtifactDigests = struct {
	sync.Mutex
	entries map[string]managedArtifactDigestEntry
	now     func() time.Time
}{now: time.Now}

func managedArtifactDigestKey(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

// rememberedManagedArtifactDigest returns the digest of path read at the
// version stamp, unless that read is managedArtifactDigestMaxAge old.
func rememberedManagedArtifactDigest(path string, stamp managedArtifactStamp) (string, bool) {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	entry, ok := managedArtifactDigests.entries[managedArtifactDigestKey(path)]
	if !ok || entry.stamp != stamp ||
		managedArtifactDigests.now().Sub(entry.at) >= managedArtifactDigestMaxAge {
		return "", false
	}
	return entry.digest, true
}

func rememberManagedArtifactDigest(path string, stamp managedArtifactStamp, digest string) {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	if managedArtifactDigests.entries == nil {
		managedArtifactDigests.entries = map[string]managedArtifactDigestEntry{}
	}
	managedArtifactDigests.entries[managedArtifactDigestKey(path)] = managedArtifactDigestEntry{
		stamp:  stamp,
		digest: digest,
		at:     managedArtifactDigests.now(),
	}
}

func forgetManagedArtifactDigest(path string) {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	delete(managedArtifactDigests.entries, managedArtifactDigestKey(path))
}

// managedArtifactDigestMemoWanted reports whether the digest of path may be
// memoized: only the enterprise hook binary, never a file of the connector
// data dir, which its user can reach.
func managedArtifactDigestMemoWanted(dataDir, path string) bool {
	return !pathInsideConnectorDataDir(dataDir, path) && managedArtifactDigestMemoEligible(path)
}

// openManagedArtifactForDigest opens path for the stable digest. With
// memoize it first opens a handle no writer can share: guarded reports it.
// No handle could write the file when that one opened and none can while it
// is open, so a stamp taken on it names the bytes read through it. A later
// write does not always change the change-journal number: while any other
// handle keeps the change epoch of the file open, a second change of the
// same kind keeps it. A full read therefore ends the epoch on this handle
// (endManagedArtifactChangeEpoch) before it takes the stamp it remembers;
// the next change then gets a new number. While a writer holds the file the
// usual open is used and nothing is memoized.
func openManagedArtifactForDigest(path string, memoize bool) (*os.File, bool, error) {
	if memoize {
		if file, err := openManagedArtifactExclusive(path); err == nil {
			return file, true, nil
		}
	}
	file, err := os.Open(path)
	return file, false, err
}
