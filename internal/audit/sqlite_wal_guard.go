// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"time"
)

// walFrameBytes is the size of one WAL frame at the default 4096-byte page:
// the page plus the 24-byte frame header.
const walFrameBytes = 4096 + 24

// auditWALJournalSizeLimitBytes is the journal_size_limit of every audit
// connection. When a writer restarts the log from its start, SQLite cuts the
// WAL file back to this size at that commit, so a burst's disk space comes
// back without waiting for the next WAL guard pass (rel-1-0-2:GAP-0709).
const auditWALJournalSizeLimitBytes = 64 << 20

// auditBusyTimeoutMillis is the busy_timeout of every audit connection.
const auditBusyTimeoutMillis = 5000

// walIdleTrimBytes is the WAL file size past which a fully copied log is cut
// to zero bytes even though it is below the caller's limit: a log that stops
// growing is never restarted by a writer, so its file kept its peak size
// while the gateway was idle. A variable so tests can use a small file.
var walIdleTrimBytes int64 = auditWALJournalSizeLimitBytes

// walCopyPasses bounds the copy passes on the dedicated connection, and
// walWriterCopyFrames is the backlog (about 8 MiB) left for the writer
// connection to copy, which it does well inside its budget.
const (
	walCopyPasses       = 3
	walWriterCopyFrames = 2048
)

// Test seams: walCopyPhaseHook runs before each copy pass and
// walWriterPhaseHook while the writer connection is held, so tests can hold
// either phase open.
var (
	walCopyPhaseHook   func(context.Context)
	walWriterPhaseHook func(context.Context)
)

// WALCheckpoint reports one CheckpointWALIfLarge pass.
type WALCheckpoint struct {
	// LogBytes is the length of the log in use when the pass started.
	LogBytes int64
	// FileBytes is the size of the WAL file on disk when the pass ended.
	FileBytes int64
	// Truncated is true when the pass copied the whole log into the database
	// and cut the WAL file to zero bytes.
	Truncated bool
}

// CheckpointWALIfLarge keeps the write-ahead log bounded under sustained hook
// traffic. The store runs with wal_autocheckpoint=0, so nothing else restarts
// the log while hooks keep writing.
//
// The pass first copies the log into the database on the dedicated checkpoint
// connection with PASSIVE checkpoints, which never hold off the writer. That
// copy is bounded only by ctx: SQLite records a checkpoint's progress when it
// finishes, so a copy cut short by a deadline starts over at the next pass. A
// 200 ms bound on the whole pass therefore stopped every copy once the log
// passed what a disk copies in 200 ms, and the log grew to tens of GiB under
// corpus load (rel-1-0-2:GAP-0709).
//
// When the log is longer than limitBytes, or it is fully copied and its file
// is larger than walIdleTrimBytes, the pass then runs a TRUNCATE checkpoint on
// the store's single writer connection within writerBudget. Only the frames
// written since the copy are left to copy, the writer connection has no other
// writer to wait for, and its busy timeout is zero for that statement, so
// hooks wait at most writerBudget. The checkpoint copies the rest, restarts
// the log and cuts the WAL file to zero bytes. A reader on an older snapshot
// makes it busy; the next pass tries again.
func (s *Store) CheckpointWALIfLarge(ctx context.Context, limitBytes int64, writerBudget time.Duration) (result WALCheckpoint, err error) {
	if ctx == nil {
		return result, fmt.Errorf("audit: WAL checkpoint context is required")
	}
	if writerBudget <= 0 {
		return result, fmt.Errorf("audit: WAL checkpoint writer budget is required")
	}
	release, err := s.acquireReady()
	if err != nil {
		return result, err
	}
	defer release()
	defer func() { result.FileBytes = s.walFileBytes() }()
	db, err := s.checkpointConn()
	if err != nil {
		return result, fmt.Errorf("audit: open SQLite checkpoint connection: %w", err)
	}
	var busy, frames, copied int
	for pass := 0; pass < walCopyPasses; pass++ {
		if walCopyPhaseHook != nil {
			walCopyPhaseHook(ctx)
		}
		if err := db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &frames, &copied); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return result, fmt.Errorf("audit: copy SQLite WAL: %w", ctxErr)
			}
			return result, fmt.Errorf("audit: copy SQLite WAL: %w", err)
		}
		if busy != 0 {
			// Another checkpoint holds the log; the next pass tries again.
			return result, nil
		}
		if pass == 0 {
			result.LogBytes = int64(frames) * walFrameBytes
		}
		if frames-copied <= walWriterCopyFrames {
			break
		}
	}
	long := int64(frames)*walFrameBytes > limitBytes
	idleOversized := frames == copied && s.walFileBytes() > walIdleTrimBytes
	if !long && !idleOversized {
		return result, nil
	}
	busy, err = s.truncateWALOnWriter(ctx, writerBudget)
	if err != nil {
		return result, err
	}
	result.Truncated = busy == 0
	return result, nil
}

// truncateWALOnWriter runs PRAGMA wal_checkpoint(TRUNCATE) on the writer
// connection within budget and returns its busy column. A TRUNCATE checkpoint
// waits in SQLite's busy handler for readers on older snapshots, and a
// deadline does not interrupt that wait, so the connection's busy timeout is
// zero for the statement and restored afterwards. A connection whose busy
// timeout cannot be restored is dropped from the pool.
func (s *Store) truncateWALOnWriter(ctx context.Context, budget time.Duration) (int, error) {
	writerCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	yielded := func(err error) error {
		if errors.Is(writerCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("audit: WAL checkpoint yielded the writer after %s: %w", budget, context.DeadlineExceeded)
		}
		return fmt.Errorf("audit: checkpoint SQLite WAL on the writer: %w", err)
	}
	conn, err := s.db.Conn(writerCtx)
	if err != nil {
		return 0, yielded(err)
	}
	defer conn.Close() //nolint:errcheck -- returns the connection to the pool.
	if _, err := conn.ExecContext(writerCtx, "PRAGMA busy_timeout = 0"); err != nil {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		return 0, yielded(err)
	}
	defer func() {
		restoreCtx, cancelRestore := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancelRestore()
		if _, err := conn.ExecContext(restoreCtx, fmt.Sprintf("PRAGMA busy_timeout = %d", auditBusyTimeoutMillis)); err != nil {
			// Hook writes on a connection without its busy timeout would fail
			// under contention. The pool opens a new one with the DSN pragmas.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	if walWriterPhaseHook != nil {
		walWriterPhaseHook(writerCtx)
	}
	var busy, frames, copied int
	if err := conn.QueryRowContext(writerCtx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &frames, &copied); err != nil {
		return 0, yielded(err)
	}
	return busy, nil
}

func (s *Store) walFileBytes() int64 {
	if s.dbPath == "" || s.dbPath == ":memory:" {
		return 0
	}
	info, err := os.Stat(s.dbPath + "-wal")
	if err != nil {
		return 0
	}
	return info.Size()
}
