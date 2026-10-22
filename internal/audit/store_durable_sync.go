// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// auditDurablePragmas are the audit pragmas with synchronous=FULL and
// fullfsync on. The store's pool runs synchronous=NORMAL: a WAL commit is
// on disk only after the next checkpoint, so a power loss can take back the
// last commits. On the durable connection SQLite flushes the whole WAL at
// every commit (with F_FULLFSYNC on macOS), which makes every commit before
// it durable too.
var auditDurablePragmas = buildAuditDurablePragmas()

func buildAuditDurablePragmas() string {
	const normal, full = "&_pragma=synchronous(NORMAL)", "&_pragma=synchronous(FULL)"
	if strings.Count(auditPragmas, normal) != 1 {
		panic("audit: the audit pragmas do not set synchronous=NORMAL once")
	}
	return strings.Replace(auditPragmas, normal, full, 1) + "&_pragma=fullfsync(1)"
}

// syncCommittedWrites makes every audit write committed before the call
// survive a power loss: it commits one readiness write on the durable
// connection (auditDurablePragmas), then flushes the database folder so a
// WAL file created since the store opened keeps its entry. A producer that
// marks an occurrence reported once it is stored (a trust anchor or
// credential change event) calls it first, so the marker never outlives
// the row. An in-memory store has nothing to flush.
func (s *Store) syncCommittedWrites(ctx context.Context) error {
	if s == nil || s.db == nil || s.dbPathGuard == nil || s.dbPathGuard.inMemory {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	release, err := s.acquireReady()
	if err != nil {
		return err
	}
	defer release()
	db, err := s.durableConn()
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, `
		UPDATE observability_store_readiness
		SET verification_generation = verification_generation + 1,
			last_verified_at = ?
		WHERE id = 1`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("audit: flush committed audit writes to disk: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return errors.New("audit: flush committed audit writes to disk: the readiness state is invalid")
	}
	if err := syncAuditDBDir(filepath.Dir(s.dbPath)); err != nil {
		return fmt.Errorf("audit: flush the audit database folder: %w", err)
	}
	return nil
}

// durableConn returns the store's synchronous=FULL connection, opened on
// first use like the checkpoint connection and closed with the store.
func (s *Store) durableConn() (*sql.DB, error) {
	s.checkpointMu.Lock()
	defer s.checkpointMu.Unlock()
	if s.durableDB != nil {
		return s.durableDB, nil
	}
	db, err := openSQLiteWithPragmas(s.dbPath, auditDurablePragmas)
	if err != nil {
		return nil, fmt.Errorf("audit: open SQLite durable connection: %w", err)
	}
	// sql.Open is lazy. Force the open, then repeat the path guard's
	// post-open checks so the cached pool is bound to the validated file.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: verify SQLite durable connection: %w", err)
	}
	if err := revalidateHardenedAuditSQLite(s.dbPathGuard); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: revalidate database paths for durable connection: %w", err)
	}
	s.durableDB = db
	return db, nil
}

// syncAuditDBDir flushes dir (fsync on POSIX; Windows journals the
// directory, and a directory handle cannot be flushed there).
func syncAuditDBDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// storedOccurrence is what the audit_events row of an occurrence keeps of
// the process that built its record: the time, run id, sidecar id, binary
// version and config generation and digest. A stored replay rebuilds the
// record from the producer's durable event and these values, so a remote
// destination gets, under the stored id, the record the row holds and not
// one stamped by the process that replays it (after a restart: another run
// and sidecar id, maybe another binary or config). The record schema
// and bucket catalog versions, bucket, event name and floor form are checked: a record this build
// cannot rebuild exactly is not sent (storedOccurrence.matches).
type storedOccurrence struct {
	timestamp         time.Time
	runID             string
	sidecarInstanceID string
	binaryVersion     string
	configGeneration  int64
	configDigest      string
	recordSchema      int
	bucket            string
	bucketCatalog     int
	eventName         string
	floorOnly         bool
}

// storedOccurrence reads the stored values of the audit_events row with
// id, and whether there is one. A store without a database holds none. A
// row whose time does not parse is an error: its record cannot be rebuilt.
func (s *Store) storedOccurrence(ctx context.Context, id string) (storedOccurrence, bool, error) {
	if s == nil || s.db == nil {
		return storedOccurrence{}, false, nil
	}
	var (
		stamp, bucket, eventName                string
		runID, sidecar, binary, digest, body    sql.NullString
		generation, recordSchema, bucketCatalog sql.NullInt64
	)
	err := s.scanRow(ctx, "audit_event_exists",
		s.db.QueryRowContext(ctx, `
			SELECT timestamp, run_id, sidecar_instance_id, binary_version, generation, content_hash,
				record_schema_version, bucket, bucket_catalog_version, event_name, payload_json
			FROM audit_events WHERE id = ? LIMIT 1`, id),
		&stamp, &runID, &sidecar, &binary, &generation, &digest, &recordSchema, &bucket, &bucketCatalog,
		&eventName, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return storedOccurrence{}, false, nil
	}
	if err != nil {
		return storedOccurrence{}, false, fmt.Errorf("audit: look up audit event %s: %w", id, err)
	}
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return storedOccurrence{}, false, fmt.Errorf("audit: audit event %s has no valid time: %w", id, err)
	}
	var payload struct {
		FloorOnly bool `json:"floor_only"`
	}
	_ = json.Unmarshal([]byte(body.String), &payload)
	return storedOccurrence{
		timestamp: at.UTC(), runID: runID.String, sidecarInstanceID: sidecar.String,
		binaryVersion: binary.String, configGeneration: generation.Int64, configDigest: digest.String,
		recordSchema: int(recordSchema.Int64), bucket: bucket, bucketCatalog: int(bucketCatalog.Int64),
		eventName: eventName, floorOnly: payload.FloorOnly,
	}, true, nil
}

// pin gives a replayed event the stored process values.
func (o storedOccurrence) pin(event *Event) {
	event.Timestamp = o.timestamp
	event.RunID = o.runID
	event.SidecarInstanceID = o.sidecarInstanceID
	event.BinaryVersion = o.binaryVersion
}

// buildContext is the config generation and digest the stored record was
// built with.
func (o storedOccurrence) buildContext() (RuntimeV8BuildContext, error) {
	if o.configGeneration < 0 {
		return RuntimeV8BuildContext{}, fmt.Errorf("audit: the stored record has an invalid config generation")
	}
	return RuntimeV8BuildContext{ConfigGeneration: uint64(o.configGeneration), ConfigDigest: o.configDigest}, nil
}

// matches checks that record, rebuilt for a replay, is the stored record:
// the same schemas, bucket, event and form (a config that now collects only
// the mandatory floor, or a build with another record schema or bucket
// catalog, builds another record), with the stored time and process values.
func (o storedOccurrence) matches(record observability.Record) error {
	provenance, correlation := record.Provenance(), record.Correlation()
	var differs string
	switch {
	case record.SchemaVersion() != o.recordSchema:
		differs = "record schema version"
	case record.BucketCatalogVersion() != o.bucketCatalog || string(record.Bucket()) != o.bucket:
		differs = "bucket"
	case string(record.EventName()) != o.eventName:
		differs = "event name"
	case record.IsFloorOnly() != o.floorOnly:
		differs = "floor form"
	case !record.Timestamp().Equal(o.timestamp):
		differs = "time"
	case correlation.RunID != o.runID || correlation.SidecarInstanceID != o.sidecarInstanceID:
		differs = "run or sidecar id"
	case provenance.BinaryVersion != o.binaryVersion || provenance.ConfigGeneration != o.configGeneration ||
		provenance.ConfigDigest != o.configDigest:
		differs = "provenance"
	default:
		return nil
	}
	return fmt.Errorf("audit: the stored record %s cannot be rebuilt exactly (its %s differs), so it is not sent again", record.RecordID(), differs)
}

type storedOccurrenceKey struct{}

// withStoredOccurrence carries the stored row of a replayed occurrence to
// the record builder.
func withStoredOccurrence(ctx context.Context, row storedOccurrence) context.Context {
	return context.WithValue(ctx, storedOccurrenceKey{}, row)
}

func storedOccurrenceFrom(ctx context.Context) (storedOccurrence, bool) {
	if ctx == nil {
		return storedOccurrence{}, false
	}
	row, ok := ctx.Value(storedOccurrenceKey{}).(storedOccurrence)
	return row, ok
}
