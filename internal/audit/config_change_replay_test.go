// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// A replay of a stored change is the stored record. After a restart the
// gateway has another run id and sidecar id, and maybe another binary and
// config; a replay stamped with them was a different record under the
// stored id, which a destination could acknowledge, after which the change
// was marked reported. It is now rebuilt with the values of the stored row.
// A record this build cannot rebuild exactly (another record schema,
// bucket catalog or event, the floor form under a config that now collects
// only the floor, a row without a valid time) is not sent, and the change
// stays queued.
func TestLogConfigChangeReplaysTheStoredRecordAfterARestart(t *testing.T) {
	previousRun, previousSidecar := gatewaylog.ProcessRunID(), ProcessAgentInstanceID()
	previousBinary := version.Current().BinaryVersion
	t.Cleanup(func() {
		gatewaylog.SetProcessRunID(previousRun)
		SetProcessAgentInstanceID(previousSidecar)
		version.SetBinaryVersion(previousBinary)
	})
	path := filepath.Join(t.TempDir(), "audit.db")
	change := ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeSecret, Action: "set",
		Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", SecretName: "splunk-hec-token"}
	start := func(run, sidecar, binary string, build *RuntimeV8BuildContext) (*Store, *Logger, *testRuntimeV8Emitter) {
		t.Helper()
		gatewaylog.SetProcessRunID(run)
		SetProcessAgentInstanceID(sidecar)
		version.SetBinaryVersion(binary)
		store, err := NewStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Init(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		logger := NewLogger(store)
		runtime := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
		runtime.build = build
		logger.SetRuntimeV8Emitter(runtime)
		return store, logger, runtime
	}
	sent := func(runtime *testRuntimeV8Emitter) []string {
		t.Helper()
		_, records := runtime.snapshot()
		out := make([]string, 0, len(records))
		for _, record := range records {
			encoded, err := record.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(encoded))
		}
		return out
	}

	first, logger, runtime := start("run-before-restart", "sidecar-before-restart", "1.0.4-dev.1", nil)
	if err := logger.LogConfigChange(change, nil); err != nil {
		t.Fatal(err)
	}
	stored := sent(runtime)
	if len(stored) != 1 || !strings.Contains(stored[0], "run-before-restart") {
		t.Fatalf("the first offer sent %v", stored)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	store, logger, runtime := start("run-after-restart", "sidecar-after-restart", "1.0.4-dev.2",
		&RuntimeV8BuildContext{ConfigGeneration: 24, ConfigDigest: strings.Repeat("b", 64)})
	if err := logger.LogConfigChange(change, nil); err != nil {
		t.Fatalf("replay after the restart: %v", err)
	}
	if replay := sent(runtime); len(replay) != 1 || replay[0] != stored[0] {
		t.Fatalf("the replay after a restart is not the stored record:\nreplay %v\nstored %s", replay, stored[0])
	}

	for name, tc := range map[string]struct {
		breakRow string
		floor    bool
	}{
		"record schema of another build": {breakRow: `UPDATE audit_events
			SET projected_record_json = json_set(projected_record_json, '$.schema_version', 0)`},
		"bucket catalog of another build": {breakRow: `UPDATE audit_events
			SET projected_record_json = json_set(projected_record_json, '$.bucket_catalog_version', 0)`},
		"another event": {breakRow: `UPDATE audit_events
			SET projected_record_json = json_set(projected_record_json, '$.event_name', 'config.trust_anchors.changed')`},
		"no valid time":  {breakRow: `UPDATE audit_events SET timestamp = 'yesterday'`},
		"floor form now": {floor: true},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(sent(runtime))
			var stamp, record string
			if err := store.db.QueryRow(`SELECT timestamp, projected_record_json FROM audit_events`).
				Scan(&stamp, &record); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				runtime.admission = router.AdmissionOrdinary
				if _, err := store.db.Exec(`UPDATE audit_events SET timestamp = ?, projected_record_json = ?`,
					stamp, record); err != nil {
					t.Fatal(err)
				}
			})
			if tc.breakRow != "" {
				if _, err := store.db.Exec(tc.breakRow); err != nil {
					t.Fatal(err)
				}
			}
			if tc.floor {
				runtime.admission = router.AdmissionFloor
			}
			if err := logger.LogConfigChange(change, nil); err == nil {
				t.Fatal("a replay that is not the stored record was accepted")
			}
			if got := sent(runtime); len(got) != before {
				t.Fatalf("a replay that is not the stored record was sent: %s", got[len(got)-1])
			}
		})
	}
	// The row is whole again: the replay is the stored record.
	if err := logger.LogConfigChange(change, nil); err != nil {
		t.Fatal(err)
	}
	if got := sent(runtime); got[len(got)-1] != stored[0] {
		t.Fatalf("the replay is not the stored record: %s", got[len(got)-1])
	}
}

// A change event id names one change. When the spool offers another event
// under an id the store already holds (the interrupted reservation of a
// change whose applied event the store has, after a power loss took the
// event file), the replay used to be built from the offered event and
// checked only for its schema, event, time and provenance, so the store's
// applied anchor record went out as failed (interrupted) under its id, and
// a body change (another hash, key or actor) went out too. Now the rebuilt
// record must be the stored one, outcome and body included, and nothing
// else is sent under its id; the stored change still replays.
func TestLogConfigChangeRefusesAnotherChangeUnderTheStoredID(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	logger := NewLogger(store)
	runtime := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	sent := func() int {
		_, records := runtime.snapshot()
		return len(records)
	}
	applied := ConfigChange{EventID: testConfigChangeID, Kind: ConfigChangeTrustAnchors, Action: "install",
		Outcome: ConfigChangeApplied, Actor: "os:uid:0:root", ChangedAt: "2026-10-21T10:00:00Z",
		SHA256: strings.Repeat("a", 64), PreviousSHA256: strings.Repeat("b", 64),
		KeyIDsAdded: []string{"bundle-key-2"}, KeyIDsRemoved: []string{"bundle-key-1"}}
	if err := logger.LogConfigChange(applied, nil); err != nil {
		t.Fatal(err)
	}
	if sent() != 1 {
		t.Fatal("the applied change was not sent")
	}
	interrupted := ConfigChange{EventID: applied.EventID, Kind: ConfigChangeTrustAnchors, Action: "install",
		Outcome: ConfigChangeFailed, ReasonCode: "interrupted", Actor: applied.Actor, ChangedAt: applied.ChangedAt}
	for name, change := range map[string]ConfigChange{
		"the interrupted reservation": interrupted,
		"a refusal":                   {EventID: applied.EventID, Kind: ConfigChangeTrustAnchors, Action: "install", Outcome: ConfigChangeRefused, ReasonCode: "bundle_signature_invalid", Actor: applied.Actor, ChangedAt: applied.ChangedAt},
		"another anchor file":         func() ConfigChange { c := applied; c.SHA256 = strings.Repeat("c", 64); return c }(),
		"another replaced file":       func() ConfigChange { c := applied; c.PreviousSHA256 = ""; return c }(),
		"another added key":           func() ConfigChange { c := applied; c.KeyIDsAdded = []string{"bundle-key-3"}; return c }(),
		"no removed key":              func() ConfigChange { c := applied; c.KeyIDsRemoved = nil; return c }(),
		"another account":             func() ConfigChange { c := applied; c.Actor = "os:uid:501:alice"; return c }(),
		"another time":                func() ConfigChange { c := applied; c.ChangedAt = "2026-10-21T11:00:00Z"; return c }(),
	} {
		before := sent()
		if err := logger.LogConfigChange(change, nil); err == nil {
			t.Fatalf("%s under the stored id was accepted", name)
		}
		if sent() != before {
			t.Fatalf("%s was sent under the stored id", name)
		}
	}
	if err := logger.LogConfigChange(applied, nil); err != nil {
		t.Fatalf("the stored change does not replay: %v", err)
	}
	if sent() != 2 {
		t.Fatal("the stored change was not sent again")
	}
}
