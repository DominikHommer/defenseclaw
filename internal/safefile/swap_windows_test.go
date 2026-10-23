// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeSwapSourceForTest(t *testing.T, dir string, data string) string {
	t.Helper()
	source := filepath.Join(dir, "source.tmp")
	if err := os.WriteFile(source, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return source
}

func requireSwapDirForTest(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		got[entry.Name()] = string(data)
	}
	if len(got) != len(want) {
		t.Fatalf("directory = %v, want %v", got, want)
	}
	for name, data := range want {
		if got[name] != data {
			t.Fatalf("directory = %v, want %v", got, want)
		}
	}
}

// A compare-and-swap replaces only the file it expects, and leaves no
// replaced copy behind.
func TestCompareAndSwapFileReplacesOnlyTheExpectedFile(t *testing.T) {
	for _, test := range []struct {
		name     string
		onDisk   *string
		expected SwapExpectation
		swapped  bool
	}{
		{name: "expected bytes", onDisk: swapTestString("old"), expected: SwapExpectation{Exists: true, Data: []byte("old")}, swapped: true},
		{name: "expected absent", expected: SwapExpectation{}, swapped: true},
		{name: "different bytes", onDisk: swapTestString("newer save"), expected: SwapExpectation{Exists: true, Data: []byte("old")}},
		{name: "file appeared", onDisk: swapTestString("newer save"), expected: SwapExpectation{}},
		{name: "file disappeared", expected: SwapExpectation{Exists: true, Data: []byte("old")}},
		{name: "longer than the limit", onDisk: swapTestString("old and more"), expected: SwapExpectation{Exists: true, Data: []byte("old")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "hooks.json")
			if test.onDisk != nil {
				if err := os.WriteFile(destination, []byte(*test.onDisk), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			source := writeSwapSourceForTest(t, dir, "new")
			result, err := CompareAndSwapFile(source, destination, test.expected, 4, nil)
			if test.swapped {
				if err != nil || !result.Swapped || result.Replaced != (test.onDisk != nil) {
					t.Fatalf("swap: %+v err=%v", result, err)
				}
				requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new"})
				return
			}
			if !errors.Is(err, ErrSwapRaced) || result.Swapped {
				t.Fatalf("swap over another file: %+v err=%v", result, err)
			}
			want := map[string]string{"source.tmp": "new"}
			if test.onDisk != nil {
				want["hooks.json"] = *test.onDisk
			}
			requireSwapDirForTest(t, dir, want)
		})
	}
}

// inspect sees the locked file before the comparison, and its error stops the
// swap with the file in place.
func TestCompareAndSwapFileInspectRefuses(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "new")
	refused := errors.New("refused")
	inspected := ""
	_, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16,
		func(file *os.File) error {
			inspected = file.Name()
			return refused
		})
	if !errors.Is(err, refused) || inspected != destination {
		t.Fatalf("inspect: name %q err=%v", inspected, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "old", "source.tmp": "new"})
}

// While a swap holds the file, another process cannot write it; a writer
// that already has the file open for writing makes the swap wait, then fail
// without changing it.
func TestCompareAndSwapFileWaitsForAnOpenWriter(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(destination, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	source := writeSwapSourceForTest(t, dir, "new")
	if _, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil); err == nil {
		t.Fatal("the swap replaced a file another writer has open for writing")
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "old", "source.tmp": "new"})
}

func TestRemoveFileIfUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if _, err := RemoveFileIfUnchanged(path, []byte("ours"), 16, nil); !errors.Is(err, ErrSwapRaced) {
		t.Fatalf("remove a missing file: %v", err)
	}
	if err := os.WriteFile(path, []byte("newer save"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveFileIfUnchanged(path, []byte("ours"), 16, nil); !errors.Is(err, ErrSwapRaced) {
		t.Fatalf("remove another file: %v", err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "newer save"})
	if err := os.WriteFile(path, []byte("ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := RemoveFileIfUnchanged(path, []byte("ours"), 16, nil); err != nil || !result.Swapped {
		t.Fatalf("remove our file: %+v err=%v", result, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{})
}

func swapTestString(value string) *string { return &value }
