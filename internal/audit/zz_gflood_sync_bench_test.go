// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// G-flood bench branch only: never merged.
package audit

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestGFloodSyncCost measures how long a file sync takes after writing n
// random or n contiguous 4 KiB pages of a 512 MiB file, the write shape of a
// WAL checkpoint (random) against a WAL append (contiguous).
func TestGFloodSyncCost(t *testing.T) {
	if os.Getenv("GFLOOD_SYNC") != "1" {
		t.Skip("bench")
	}
	dir := os.Getenv("GFLOOD_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	path := filepath.Join(dir, "gflood-sync.db")
	defer os.Remove(path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const size = int64(512 << 20)
	chunk := make([]byte, 1<<20)
	for off := int64(0); off < size; off += int64(len(chunk)) {
		if _, err := f.WriteAt(chunk, off); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	page := make([]byte, 4096)
	pages := size / 4096
	rng := rand.New(rand.NewPCG(1, 2))
	timeSync := func() time.Duration {
		began := time.Now()
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		return time.Since(began)
	}
	t.Logf("dir=%s clean sync=%v", dir, timeSync())
	for _, n := range []int{10, 100, 300, 1000, 3000} {
		for rep := 0; rep < 3; rep++ {
			for range n {
				if _, err := f.WriteAt(page, rng.Int64N(pages)*4096); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("random pages=%d sync=%v", n, timeSync())
		}
		start := rng.Int64N(pages - int64(n))
		for i := range n {
			if _, err := f.WriteAt(page, (start+int64(i))*4096); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("contiguous pages=%d sync=%v", n, timeSync())
	}
	// Random writes from a second goroutine while syncing: does a sync wait
	// for writes that land during it?
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = f.WriteAt(page, rng.Int64N(pages)*4096)
			time.Sleep(250 * time.Microsecond)
		}
	}()
	for rep := 0; rep < 10; rep++ {
		time.Sleep(200 * time.Millisecond)
		t.Logf("under 4000 random writes/s sync=%v", timeSync())
	}
	close(stop)
	wg.Wait()
	t.Logf("after load clean sync=%v", timeSync())
}
