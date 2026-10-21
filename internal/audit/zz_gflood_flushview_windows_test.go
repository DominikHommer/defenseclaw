// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// G-flood bench branch only: never merged.
package audit

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// flushViewParallel maps the whole file and flushes it in parts from several
// goroutines, so Windows writes the dirty cached pages with more than one
// write in flight.
func flushViewParallel(t *testing.T, f *os.File, size int64, parts int, access uint32, protect uint32) time.Duration {
	began := time.Now()
	mapping, err := windows.CreateFileMapping(windows.Handle(f.Fd()), nil, protect, 0, 0, nil)
	if err != nil {
		t.Fatalf("CreateFileMapping: %v", err)
	}
	defer windows.CloseHandle(mapping)
	addr, err := windows.MapViewOfFile(mapping, access, 0, 0, uintptr(size))
	if err != nil {
		t.Fatalf("MapViewOfFile: %v", err)
	}
	defer windows.UnmapViewOfFile(addr)
	chunk := (size/int64(parts) + 65535) &^ 65535
	var wg sync.WaitGroup
	for off := int64(0); off < size; off += chunk {
		n := min(chunk, size-off)
		wg.Add(1)
		go func(off, n int64) {
			defer wg.Done()
			if err := windows.FlushViewOfFile(addr+uintptr(off), uintptr(n)); err != nil {
				t.Errorf("FlushViewOfFile: %v", err)
			}
		}(off, n)
	}
	wg.Wait()
	_ = unsafe.Pointer(nil)
	return time.Since(began)
}

func TestGFloodFlushViewCost(t *testing.T) {
	if os.Getenv("GFLOOD_SYNC") != "1" {
		t.Skip("bench")
	}
	dir := os.Getenv("GFLOOD_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	path := filepath.Join(dir, "gflood-view.db")
	defer os.Remove(path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const size = int64(512 << 20)
	buf := make([]byte, 1<<20)
	for off := int64(0); off < size; off += int64(len(buf)) {
		if _, err := f.WriteAt(buf, off); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	page := make([]byte, 4096)
	pages := size / 4096
	rng := rand.New(rand.NewPCG(3, 4))
	dirty := func(n int) {
		for range n {
			if _, err := f.WriteAt(page, rng.Int64N(pages)*4096); err != nil {
				t.Fatal(err)
			}
		}
	}
	timeSync := func() time.Duration {
		began := time.Now()
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		return time.Since(began)
	}
	for _, n := range []int{300, 1000} {
		dirty(n)
		t.Logf("dir=%s pages=%d FlushFileBuffers alone=%v", dir, n, timeSync())
		for _, parts := range []int{1, 8, 32} {
			dirty(n)
			view := flushViewParallel(t, f, size, parts, windows.FILE_MAP_READ, windows.PAGE_READONLY)
			t.Logf("dir=%s pages=%d read-only view parts=%d flush=%v then FlushFileBuffers=%v", dir, n, parts, view, timeSync())
			dirty(n)
			view = flushViewParallel(t, f, size, parts, windows.FILE_MAP_WRITE, windows.PAGE_READWRITE)
			t.Logf("dir=%s pages=%d read-write view parts=%d flush=%v then FlushFileBuffers=%v", dir, n, parts, view, timeSync())
		}
	}
}
