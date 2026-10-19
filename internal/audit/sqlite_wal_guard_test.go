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
// size on disk until a manual TRUNCATE (rel-1-0-2:GAP-0709). The pass after
// the last write trims it.
func TestCheckpointWALIfLargeTrimsAnIdleOversizedFile(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	grown := walFileSize(t, store)
	original := walIdleTrimBytes
	walIdleTrimBytes = grown / 2
	t.Cleanup(func() { walIdleTrimBytes = original })
	// The log is longer than a trickle's.
	originalCopyFrames := walWriterCopyFrames
	walWriterCopyFrames = 16
	t.Cleanup(func() { walWriterCopyFrames = originalCopyFrames })
	ctx := context.Background()
	pass, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || pass.Truncated || pass.WriterHeld != 0 || pass.FileBytes != grown {
		t.Fatalf("first pass after the writes: %+v, %v; want the copy only", pass, err)
	}
	pass, err = store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || !pass.Truncated || pass.FileBytes != 0 {
		t.Fatalf("idle oversized WAL: %+v, %v; want it truncated", pass, err)
	}
}

// A trickle of background writes after a flood restarts the log, so the
// store is never quiet for a whole pass. The file is still trimmed once the
// log in use is short and copied.
func TestCheckpointWALIfLargeTrimsAnOversizedFileUnderATrickleOfWrites(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	logWALGuardEvents(t, store, 200)
	grown := walFileSize(t, store)
	original := walIdleTrimBytes
	walIdleTrimBytes = grown / 2
	t.Cleanup(func() { walIdleTrimBytes = original })
	if _, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget); err != nil {
		t.Fatal(err)
	}
	// One write restarts the fully copied log; the file keeps its size.
	logWALGuardEvents(t, store, 1)
	if size := walFileSize(t, store); size != grown {
		t.Fatalf("WAL file after the trickle write = %d bytes, want %d", size, grown)
	}
	pass, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || !pass.Truncated || pass.FileBytes != 0 {
		t.Fatalf("oversized file under a trickle: %+v, %v; want it truncated", pass, err)
	}
}

// countWriterPhases counts the passes that take the writer connection.
func countWriterPhases(t *testing.T) *int {
	t.Helper()
	var count int
	original := walWriterPhaseHook
	walWriterPhaseHook = func(context.Context) { count++ }
	t.Cleanup(func() { walWriterPhaseHook = original })
	return &count
}

// rel-1-0-3 GAP-0247, GAP-0136: under sustained hook writes the WAL file stays
// over walIdleTrimBytes, and the idle trim took the writer connection for a
// sync on every pass. The hooks queued behind those syncs and their latency
// rose for the whole flood. A pass with writes since the previous pass and a
// log under the limit only copies.
func TestCheckpointWALIfLargeDoesNotHoldTheWriterForAnOversizedFileUnderWrites(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	original := walIdleTrimBytes
	walIdleTrimBytes = walFileSize(t, store) / 4
	t.Cleanup(func() { walIdleTrimBytes = original })
	// A flood writes more between two passes than the writer copy bound.
	originalCopyFrames := walWriterCopyFrames
	walWriterCopyFrames = 16
	t.Cleanup(func() { walWriterCopyFrames = originalCopyFrames })
	phases := countWriterPhases(t)
	ctx := context.Background()
	for pass := range 5 {
		logWALGuardEvents(t, store, 20)
		result, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
		if err != nil || result.Truncated || result.Restarted || result.WriterHeld != 0 || *phases != 0 {
			t.Fatalf("pass %d under writes: %+v, %v, writer phases %d; want the copy only", pass, result, err, *phases)
		}
		if result.FileBytes <= walIdleTrimBytes {
			t.Fatalf("pass %d: WAL file %d bytes is not over the trim size %d", pass, result.FileBytes, walIdleTrimBytes)
		}
	}
	// The pass after the writes stop trims the file.
	result, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || !result.Truncated || result.FileBytes != 0 || *phases != 1 {
		t.Fatalf("pass after the writes stopped: %+v, %v, writer phases %d; want one trim", result, err, *phases)
	}
}

// A log over the limit under writes is restarted on the writer, not cut to
// zero bytes: the next write starts the log again from its start, and the
// file keeps its space for the writes that follow.
func TestCheckpointWALIfLargeRestartsALongLogUnderWrites(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	logWALGuardEvents(t, store, 200)
	if _, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget); err != nil {
		t.Fatal(err)
	}
	logWALGuardEvents(t, store, 50)
	phases := countWriterPhases(t)
	pass, err := store.CheckpointWALIfLarge(ctx, 0, testWALWriterBudget)
	if err != nil || !pass.Restarted || pass.Truncated || pass.FileBytes == 0 || *phases != 1 || pass.WriterHeld <= 0 {
		t.Fatalf("long log under writes: %+v, %v, writer phases %d; want one restart that keeps the file", pass, err, *phases)
	}
	logWALGuardEvents(t, store, 1)
	next, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || next.LogBytes <= 0 || next.LogBytes >= pass.LogBytes/10 {
		t.Fatalf("log after the restart and one write = %+v, %v; want it started again (was %d bytes)", next, err, pass.LogBytes)
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM audit_events WHERE target = 'wal-guard'`).Scan(&count); err != nil || count != 251 {
		t.Fatalf("events after the restart = %d, %v; want 251", count, err)
	}
}

// A long log whose copy left more than walWriterCopyFrames is not restarted
// on the writer, which would hold the hooks for the whole copy, until it is
// past walForcedRestartFactor times the limit.
func TestCheckpointWALIfLargeHoldsTheWriterOnlyForASmallBacklog(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	logWALGuardEvents(t, store, 200)
	original := walWriterCopyFrames
	walWriterCopyFrames = -1 // every backlog is too large
	t.Cleanup(func() { walWriterCopyFrames = original })
	phases := countWriterPhases(t)
	// No pass has copied the log yet, so it fills the file.
	logBytes := walFileSize(t, store)
	pass, err := store.CheckpointWALIfLarge(ctx, logBytes*2/3, testWALWriterBudget)
	if err != nil || !pass.WriterDeferred || pass.Restarted || pass.WriterHeld != 0 || *phases != 0 {
		t.Fatalf("long log with a large backlog: %+v, %v, writer phases %d; want the restart deferred", pass, err, *phases)
	}
	pass, err = store.CheckpointWALIfLarge(ctx, logBytes/3, testWALWriterBudget)
	if err != nil || pass.WriterDeferred || !pass.Restarted || *phases != 1 {
		t.Fatalf("log past %dx the limit: %+v, %v, writer phases %d; want the restart", walForcedRestartFactor, pass, err, *phases)
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
	if err != nil || !pass.Restarted {
		t.Fatalf("slow copy: %+v, %v; want the log restarted", pass, err)
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
