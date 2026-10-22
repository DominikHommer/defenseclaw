// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"time"
)

// logDurableActivity retires a producer's spool record only after confirmed
// delivery and a power-loss barrier for its canonical local row.
func (l *Logger) logDurableActivity(in ActivityInput) error {
	if err := l.logActivityImpl(in); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return l.store.SyncEventHistory(ctx)
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
