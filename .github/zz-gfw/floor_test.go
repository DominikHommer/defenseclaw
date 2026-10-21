// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// G-flood-wal bench branch only: never merged.
package audit

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestGFWSyncFloor measures one file sync after k dirty 4 KiB pages of a
// 256 MiB file, random and contiguous, median of 15.
func TestGFWSyncFloor(t *testing.T) {
	if os.Getenv("GFW_SYNC_FLOOR") != "1" {
		t.Skip("bench")
	}
	path := filepath.Join(t.TempDir(), "floor.db")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	const pages = 65536
	page := make([]byte, 4096)
	chunk := make([]byte, 1<<20)
	for offset := int64(0); offset < pages*4096; offset += int64(len(chunk)) {
		if _, err := file.WriteAt(chunk, offset); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"random", "contiguous"} {
		for _, k := range []int{0, 1, 5, 20, 50, 200, 1000} {
			var times []time.Duration
			for range 15 {
				start := rand.IntN(pages - k - 1)
				for i := range k {
					index := start + i
					if mode == "random" {
						index = rand.IntN(pages)
					}
					page[0]++
					if _, err := file.WriteAt(page, int64(index)*4096); err != nil {
						t.Fatal(err)
					}
				}
				began := time.Now()
				if err := file.Sync(); err != nil {
					t.Fatal(err)
				}
				times = append(times, time.Since(began))
			}
			slices.Sort(times)
			t.Logf("sync floor %s k=%d median=%v min=%v max=%v", mode, k, times[len(times)/2], times[0], times[len(times)-1])
		}
	}
}
