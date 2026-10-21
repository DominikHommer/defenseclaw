// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The spellings of one folder share a key (GAP-0626): case, the \\?\ prefix,
// a trailing separator and an 8.3 short name.
func TestComparisonKeyFoldsSpellingsOfOneFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "WinGet Packages Folder")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := ComparisonKey(dir)
	spellings := []string{
		strings.ToUpper(dir),
		`\\?\` + dir,
		dir + `\`,
		filepath.ToSlash(dir),
	}
	if short, ok := shortPathName(dir); ok && short != dir {
		spellings = append(spellings, short, `\\?\`+short)
	}
	for _, spelling := range spellings {
		if got := ComparisonKey(spelling); got != want {
			t.Fatalf("ComparisonKey(%q) = %q, want %q", spelling, got, want)
		}
	}
	if got := ComparisonKey(`\\?\UNC\server\share\dir`); got != `\\server\share\dir` {
		t.Fatalf("UNC key = %q", got)
	}
	if ComparisonKey(dir+"2") == want {
		t.Fatal("another folder shares the key")
	}
}

// A long-name lookup on storage that never answers must not hold
// ComparisonKey: the WinGet scan computes its slot key before its own
// deadline starts, and the guardian keys its pending restores (B-21 review).
func TestComparisonKeyDoesNotWaitForAStalledLongNameLookup(t *testing.T) {
	oldLookups, oldLookup := longNames, getLongPathName
	release := make(chan struct{})
	longNames = newLongNameLookups()
	getLongPathName = func(string) (string, bool) {
		<-release
		return `C:\Users\Stalled Profile\AppData\Local\Microsoft\WinGet\Packages`, true
	}
	t.Cleanup(func() {
		close(release)
		longNames, getLongPathName = oldLookups, oldLookup
	})
	path := `C:\Users\STALLE~1\AppData\Local\Microsoft\WinGet\Packages`
	want := strings.ToLower(path)
	for i := 0; i < 2; i++ {
		started := time.Now()
		if got := ComparisonKey(path); got != want {
			t.Fatalf("ComparisonKey = %q, want %q", got, want)
		}
		if waited := time.Since(started); waited > longNameLookupBudget+2*time.Second {
			t.Fatalf("ComparisonKey waited %v for a stalled lookup", waited)
		}
	}
}

func shortPathName(path string) (string, bool) {
	long, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", false
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(long, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		return "", false
	}
	return windows.UTF16ToString(buffer[:n]), true
}
