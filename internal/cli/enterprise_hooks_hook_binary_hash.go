// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"
	"time"
)

// hookFileStamp is what the file system reports about one version of a file
// without reading it: the volume and file id, size, link count, last-write
// and change times, attributes and, on a volume with a change journal, the
// update sequence number of the file. A write, truncation, rename over the
// file or attribute change gives a different stamp.
type hookFileStamp struct {
	Volume     uint32
	ID         uint64
	Size       int64
	Links      uint32
	Written    int64
	Changed    int64
	USN        int64
	Attributes uint32
}

// hookFileHashCache remembers the SHA-256 of the files the Windows guardian
// keeps, with the stamp each file had when it was read. The guardian checks
// the 126 MB hook binary every few seconds and read all of it each time, and
// read it twice more before every reconcile, so the first reconcile on a busy
// device ran past the Setup coverage wait (GAP-0401). A file with an
// unchanged stamp is not read again until maxAge has passed since its last
// full read; that periodic read covers a writer that forges every time stamp
// on a volume without a change journal. Callers serialize use.
type hookFileHashCache struct {
	stamp   func(path string) (hookFileStamp, error)
	hash    func(path string) (string, error)
	now     func() time.Time
	maxAge  time.Duration
	entries map[string]hookFileHashEntry
}

type hookFileHashEntry struct {
	stamp    hookFileStamp
	sum      string
	hashedAt time.Time
}

// sha256 returns the SHA-256 of path. It reads the file again only when the
// stamp changed or could not be taken, or the last read is older than maxAge.
func (c *hookFileHashCache) sha256(path string) (string, error) {
	key := strings.ToLower(filepath.Clean(path))
	before, stampErr := c.stamp(path)
	now := c.now()
	if entry, ok := c.entries[key]; ok && stampErr == nil && entry.stamp == before &&
		now.Sub(entry.hashedAt) < c.maxAge {
		return entry.sum, nil
	}
	delete(c.entries, key)
	sum, err := c.hash(path)
	if err != nil || stampErr != nil {
		return sum, err
	}
	// A file that changed while it was read is read again next time.
	if after, err := c.stamp(path); err == nil && after == before {
		if c.entries == nil {
			c.entries = map[string]hookFileHashEntry{}
		}
		c.entries[key] = hookFileHashEntry{stamp: before, sum: sum, hashedAt: now}
	}
	return sum, nil
}
