// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const (
	// auditWALGuardInterval is how often the audit write-ahead log's active
	// frame count is checked on its dedicated checkpoint connection.
	auditWALGuardInterval = 2 * time.Second
	// auditWALLimitBytes is the size past which the log is checkpointed and
	// its file truncated. A busy gateway writes about 3.4 MB of log per hook
	// decision, so this is the log of roughly 75 hooks.
	auditWALLimitBytes = 256 << 20
	// auditWALWriterBudget bounds the part of a pass that holds the audit
	// store's only writer connection. Hooks need that connection for
	// correlation and their verdict records, so never let maintenance consume
	// a hook's three-second budget.
	auditWALWriterBudget = 200 * time.Millisecond
	// auditWALCopyTimeout bounds the copy on the dedicated checkpoint
	// connection, which does not hold off the writer. SQLite keeps a
	// checkpoint's progress only when it finishes, so this must be long enough
	// to copy a log many times the limit: under the writer's 200 ms budget the
	// copy never finished once the log was large, and the log grew without
	// bound (rel-1-0-2:GAP-0709).
	auditWALCopyTimeout = 2 * time.Minute
	// auditWALAlarmBytes is the WAL file size that means checkpoints are not
	// keeping up. A pass truncates the file once the log passes the limit, so
	// a healthy gateway stays far below it.
	auditWALAlarmBytes = 4 * auditWALLimitBytes
	// auditWALAlarmRepeat is how often a WAL that stays over the bound is
	// reported again.
	auditWALAlarmRepeat = 10 * time.Minute
)

// auditWALCheckpointer is the part of *audit.Store the WAL guard uses.
type auditWALCheckpointer interface {
	CheckpointWALIfLarge(ctx context.Context, limitBytes int64, writerBudget time.Duration) (audit.WALCheckpoint, error)
}

// runAuditWALGuard keeps the audit database's write-ahead log bounded under
// sustained hook traffic (see audit.Store.CheckpointWALIfLarge).
func (s *Sidecar) runAuditWALGuard(ctx context.Context) {
	if s == nil || s.store == nil || s.currentConfig().SecureClientIntegration() {
		return
	}
	ticker := time.NewTicker(auditWALGuardInterval)
	defer ticker.Stop()
	var alarm auditWALAlarm
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// A signed bundle's config rename starts this gate before its
		// generation rebuild. Defer maintenance until that swap has settled.
		if !configReloadInFlight.wait(0) {
			continue
		}
		auditWALGuardPass(ctx, s.store, &alarm, time.Now(), os.Stderr)
	}
}

// auditWALGuardPass runs one checkpoint pass and reports its outcome.
func auditWALGuardPass(ctx context.Context, store auditWALCheckpointer, alarm *auditWALAlarm, now time.Time, log io.Writer) {
	copyCtx, cancel := context.WithTimeout(ctx, auditWALCopyTimeout)
	pass, err := store.CheckpointWALIfLarge(copyCtx, auditWALLimitBytes, auditWALWriterBudget)
	cancel()
	if ctx.Err() != nil {
		return
	}
	// A pass that yields is retried at the next tick; the dedicated
	// connection's copy is kept.
	if errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(log, "[sidecar] audit WAL checkpoint yielded: %v\n", err)
	} else if err != nil {
		fmt.Fprintf(log, "[sidecar] audit WAL checkpoint failed: %v\n", err)
	}
	if line := alarm.observe(now, pass.FileBytes); line != "" {
		fmt.Fprintln(log, line)
	}
}

// auditWALAlarm says when the audit WAL file passes auditWALAlarmBytes, again
// every auditWALAlarmRepeat while it stays there, and once when it is back.
type auditWALAlarm struct {
	raised   bool
	reported time.Time
}

func (a *auditWALAlarm) observe(now time.Time, walBytes int64) string {
	if walBytes > auditWALAlarmBytes {
		if a.raised && now.Sub(a.reported) < auditWALAlarmRepeat {
			return ""
		}
		a.raised, a.reported = true, now
		return fmt.Sprintf("[sidecar] WARNING: the audit WAL file is %d MiB, over its %d MiB bound: checkpoints are not keeping up with audit writes. "+
			"A process that keeps audit.db open for reading can cause this; check free disk space",
			walBytes>>20, int64(auditWALAlarmBytes)>>20)
	}
	if a.raised {
		a.raised = false
		return fmt.Sprintf("[sidecar] the audit WAL file is back under its %d MiB bound (%d MiB)", int64(auditWALAlarmBytes)>>20, walBytes>>20)
	}
	return ""
}
