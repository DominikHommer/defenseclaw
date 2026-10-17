// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"math"
	"os"
	"testing"
	"time"
)

// The periodic size check must use the checkpoint connection even when the
// WAL is below the restart limit. A busy checkpoint must not hold the only
// audit writer connection needed by hook correlation and decision writes.
func TestCheckpointWALSizeCheckDoesNotHoldAuditWriter(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "before-checkpoint"}); err != nil {
		t.Fatal(err)
	}
	checkpointDB, err := store.checkpointConn()
	if err != nil {
		t.Fatal(err)
	}
	// Reserve the dedicated pool to simulate a slow in-progress checkpoint.
	tx, err := checkpointDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	guardDone := make(chan error, 1)
	go func() {
		_, err := store.CheckpointWALIfLarge(t.Context(), math.MaxInt64, testWALWriterBudget)
		guardDone <- err
	}()
	select {
	case err := <-guardDone:
		t.Fatalf("WAL size check did not wait for checkpoint connection: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	appendDone := make(chan error, 1)
	go func() {
		appendDone <- store.LogEvent(Event{Action: "hook_decision", Target: "during-checkpoint"})
	}()
	select {
	case err := <-appendDone:
		if err != nil {
			t.Fatalf("hook audit append failed during checkpoint: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("hook audit append waited for checkpoint")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-guardDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WAL size check did not finish after checkpoint connection was released")
	}
}

const testWALWriterBudget = 200 * time.Millisecond

func logWALGuardEvents(t *testing.T, store *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := store.LogEvent(Event{Action: "hook_decision", Target: "wal-guard", Severity: "INFO", SessionID: "s"}); err != nil {
			t.Fatalf("LogEvent: %v", err)
		}
	}
}

func walFileSize(t *testing.T, store *Store) int64 {
	t.Helper()
	info, err := os.Stat(store.dbPath + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestCheckpointWALIfLargeTruncatesTheLogOnlyWhenItIsLong(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	grown := walFileSize(t, store)
	if grown < 1<<20 {
		t.Fatalf("WAL did not grow without a checkpoint: %d bytes", grown)
	}
	ctx := context.Background()
	pass, err := store.CheckpointWALIfLarge(ctx, grown+1, testWALWriterBudget)
	if err != nil || pass.Truncated || pass.LogBytes == 0 || pass.FileBytes != grown {
		t.Fatalf("below the limit: %+v, %v; want a no-op that reports the log", pass, err)
	}
	pass, err = store.CheckpointWALIfLarge(ctx, grown/2, testWALWriterBudget)
	if err != nil || !pass.Truncated || pass.FileBytes != 0 {
		t.Fatalf("over the limit: %+v, %v; want the WAL file truncated", pass, err)
	}
	// The next writes start the log again from an empty file.
	logWALGuardEvents(t, store, 50)
	if size := walFileSize(t, store); size >= grown {
		t.Fatalf("WAL is %d bytes after the truncation, want under %d", size, grown)
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM audit_events WHERE target = 'wal-guard'`).Scan(&count); err != nil || count != 250 {
		t.Fatalf("events after the truncation = %d, %v; want 250", count, err)
	}
}

// An idle gateway never restarts the log, so a fully copied WAL kept its peak
// size on disk until a manual TRUNCATE (rel-1-0-2:GAP-0709).
func TestCheckpointWALIfLargeTrimsAnIdleOversizedFile(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	grown := walFileSize(t, store)
	original := walIdleTrimBytes
	walIdleTrimBytes = grown / 2
	t.Cleanup(func() { walIdleTrimBytes = original })
	pass, err := store.CheckpointWALIfLarge(context.Background(), math.MaxInt64, testWALWriterBudget)
	if err != nil || !pass.Truncated || pass.FileBytes != 0 {
		t.Fatalf("idle oversized WAL: %+v, %v; want it truncated", pass, err)
	}
}

// rel-1-0-2:GAP-0709: the copy on the dedicated connection is not bounded by
// the writer budget. A deadline loses all of a checkpoint's progress, so a
// copy that takes longer than the budget must still finish.
func TestCheckpointWALIfLargeCopyIsNotBoundByTheWriterBudget(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	original := walCopyPhaseHook
	walCopyPhaseHook = func(context.Context) { time.Sleep(3 * testWALWriterBudget) }
	t.Cleanup(func() { walCopyPhaseHook = original })
	pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
	if err != nil || !pass.Truncated {
		t.Fatalf("slow copy: %+v, %v; want the log truncated", pass, err)
	}
}

// The writer phase gives the writer connection back within its budget, and
// the connection keeps its busy timeout afterwards.
func TestCheckpointWALIfLargeWriterPhaseYieldsWithinBudget(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	entered := make(chan struct{})
	original := walWriterPhaseHook
	walWriterPhaseHook = func(ctx context.Context) {
		close(entered)
		<-ctx.Done()
	}
	t.Cleanup(func() { walWriterPhaseHook = original })
	passDone := make(chan error, 1)
	go func() {
		_, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		passDone <- err
	}()
	<-entered
	started := time.Now()
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "during-writer-phase"}); err != nil {
		t.Fatalf("hook audit append during the writer phase: %v", err)
	}
	if elapsed := time.Since(started); elapsed > testWALWriterBudget+time.Second {
		t.Fatalf("hook audit append waited %s for the writer phase, budget %s", elapsed, testWALWriterBudget)
	}
	if err := <-passDone; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("writer phase error = %v, want a deadline", err)
	}
	walWriterPhaseHook = original
	var timeout int
	if err := store.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != auditBusyTimeoutMillis {
		t.Fatalf("writer busy_timeout after the pass = %d, %v; want %d", timeout, err, auditBusyTimeoutMillis)
	}
}

func TestAuditConnectionsBoundTheWALFile(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	var limit int64
	if err := store.db.QueryRow(`PRAGMA journal_size_limit`).Scan(&limit); err != nil || limit != auditWALJournalSizeLimitBytes {
		t.Fatalf("journal_size_limit = %d, %v; want %d", limit, err, auditWALJournalSizeLimitBytes)
	}
}
