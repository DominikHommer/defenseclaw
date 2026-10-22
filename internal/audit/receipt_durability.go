// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"time"
)

// A replayable producer (the gateway's bundle receipt and change reporter)
// retires a spool item only after two phases. persistSpooledActivity writes
// the canonical local row, records the destinations the row owes before the
// commit, and establishes a power-loss barrier; it never waits on a
// destination, so a stalled destination cannot delay local audit history.
// confirmSpooledActivity then delivers that row and returns once every
// destination it owes acknowledged it.

const spoolPersistTimeout = 10 * time.Second

func (l *Logger) persistSpooledActivity(in ActivityInput) error {
	ctx, cancel := context.WithTimeout(context.Background(), spoolPersistTimeout)
	defer cancel()
	if err := l.logActivity(ctx, in, &spoolPhase{}); err != nil {
		return err
	}
	return l.store.SyncEventHistory(ctx)
}

func (l *Logger) confirmSpooledActivity(ctx context.Context, in ActivityInput) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := l.logActivity(ctx, in, &spoolPhase{confirm: true}); err != nil {
		return err
	}
	l.forgetSpoolObligations(in.OccurrenceID)
	return nil
}

// SyncEventHistory establishes a power-loss barrier before a producer retires
// its durable receipt. NORMAL WAL commits alone do not establish that barrier.
// SQLite's FULL checkpoint syncs the WAL before copying and syncing the DB;
// busy or incomplete checkpoints must leave the receipt available for replay.
func (s *Store) SyncEventHistory(ctx context.Context) error {
	release, err := s.acquireReady()
	if err != nil {
		return err
	}
	defer release()
	var busy, frames, copied int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(FULL)").Scan(&busy, &frames, &copied); err != nil {
		return err
	}
	if busy != 0 || frames != copied {
		return fmt.Errorf("audit: receipt durability checkpoint is incomplete")
	}
	return s.syncDatabaseFile()
}
