// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeHookFiles is a file system for hookFileHashCache: a stamp and content
// per path (matched without case, as on Windows), and a count of full reads.
type fakeHookFiles struct {
	stamps   map[string]hookFileStamp
	contents map[string]string
	stampErr error
	reads    int
	// onRead runs during a read, as a write while the file is read would.
	onRead func()
	clock  time.Time
}

func newFakeHookFileCache(files *fakeHookFiles) *hookFileHashCache {
	return &hookFileHashCache{
		stamp: func(path string) (hookFileStamp, error) {
			if files.stampErr != nil {
				return hookFileStamp{}, files.stampErr
			}
			return files.stamps[strings.ToLower(path)], nil
		},
		hash: func(path string) (string, error) {
			files.reads++
			if files.onRead != nil {
				files.onRead()
			}
			content, ok := files.contents[strings.ToLower(path)]
			if !ok {
				return "", errors.New("missing")
			}
			return "sum-" + content, nil
		},
		now:    func() time.Time { return files.clock },
		maxAge: 10 * time.Minute,
	}
}

// GAP-0401: the guardian reads an unchanged hook binary once, reads it again
// when its stamp changes (a same-size replacement or a time stamp change),
// and never keeps a sum it could not tie to one stamp.
func TestHookFileHashCacheReadsOnlyChangedFiles(t *testing.T) {
	const path = `c:\program files\cisco\defenseclaw\bin\defenseclaw-hook.exe`
	release := hookFileStamp{Volume: 7, ID: 42, Size: 126782474, Links: 1, Written: 100, Changed: 100, USN: 5000, Attributes: 0x20}
	files := &fakeHookFiles{
		stamps:   map[string]hookFileStamp{path: release},
		contents: map[string]string{path: "release"},
		clock:    time.Unix(1_800_000_000, 0),
	}
	cache := newFakeHookFileCache(files)
	sum := func() string {
		t.Helper()
		got, err := cache.sha256(path)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	for range 5 {
		if got := sum(); got != "sum-release" {
			t.Fatalf("sum = %q", got)
		}
	}
	if files.reads != 1 {
		t.Fatalf("an unchanged binary was read %d times, want 1", files.reads)
	}
	// The path is matched case-insensitively, as Windows does.
	if got, err := cache.sha256(`C:\Program Files\Cisco\DefenseClaw\bin\DEFENSECLAW-HOOK.EXE`); err != nil || got != "sum-release" || files.reads != 1 {
		t.Fatalf("other case: %q, %v, reads %d", got, err, files.reads)
	}

	// A replacement of the same size whose last-write time was set back is
	// still another file version: its change time and journal number differ.
	replaced := release
	replaced.Changed, replaced.USN = 200, 5100
	files.stamps[path], files.contents[path] = replaced, "other"
	if got := sum(); got != "sum-other" || files.reads != 2 {
		t.Fatalf("same-size replacement: %q after %d reads", got, files.reads)
	}

	// A time-stamp-only change reads the file once more and keeps the sum.
	touched := replaced
	touched.Written, touched.Changed, touched.USN = 300, 300, 5200
	files.stamps[path] = touched
	if got := sum(); got != "sum-other" || files.reads != 3 {
		t.Fatalf("time stamp change: %q after %d reads", got, files.reads)
	}
	if got := sum(); got != "sum-other" || files.reads != 3 {
		t.Fatalf("after the time stamp change: %q after %d reads", got, files.reads)
	}

	// An unchanged file is read in full again after maxAge.
	files.clock = files.clock.Add(10 * time.Minute)
	if got := sum(); got != "sum-other" || files.reads != 4 {
		t.Fatalf("after maxAge: %q after %d reads", got, files.reads)
	}
	if got := sum(); got != "sum-other" || files.reads != 4 {
		t.Fatalf("right after the full read: %q after %d reads", got, files.reads)
	}
}

func TestHookFileHashCacheKeepsNoSumItCannotTieToOneStamp(t *testing.T) {
	const path = `c:\bin\defenseclaw-hook.exe`
	first := hookFileStamp{ID: 1, Size: 10, Written: 1, Changed: 1, USN: 1}
	files := &fakeHookFiles{
		stamps:   map[string]hookFileStamp{path: first},
		contents: map[string]string{path: "a"},
	}
	cache := newFakeHookFileCache(files)

	// The file changed while it was read: the next check reads it again.
	files.onRead = func() {
		files.onRead = nil
		changed := first
		changed.USN = 2
		files.stamps[path] = changed
	}
	if _, err := cache.sha256(path); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.sha256(path); err != nil || files.reads != 2 {
		t.Fatalf("a file changed during the read was not read again: reads %d, %v", files.reads, err)
	}

	// Without a stamp every check reads the file.
	files.stampErr = errors.New("no attributes")
	for range 3 {
		if got, err := cache.sha256(path); err != nil || got != "sum-a" {
			t.Fatalf("without a stamp: %q, %v", got, err)
		}
	}
	if files.reads != 5 {
		t.Fatalf("without a stamp the file was read %d times, want 5", files.reads)
	}

	// A failed read is returned and nothing is kept.
	files.stampErr = nil
	delete(files.contents, path)
	if _, err := cache.sha256(path); err == nil {
		t.Fatal("a failed read returned no error")
	}
	if _, ok := cache.entries[`c:\bin\defenseclaw-hook.exe`]; ok {
		t.Fatal("a failed read left a sum")
	}
}
