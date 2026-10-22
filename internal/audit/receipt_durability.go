// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
)

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
