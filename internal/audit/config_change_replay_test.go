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
		"record schema of another build":  {breakRow: `UPDATE audit_events SET record_schema_version = record_schema_version + 1`},
		"bucket catalog of another build": {breakRow: `UPDATE audit_events SET bucket_catalog_version = bucket_catalog_version + 1`},
		"another event":                   {breakRow: `UPDATE audit_events SET event_name = 'config.trust_anchors.changed'`},
		"no valid time":                   {breakRow: `UPDATE audit_events SET timestamp = 'yesterday'`},
		"floor form now":                  {floor: true},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(sent(runtime))
			var stamp, event string
			var schema, catalog int
			if err := store.db.QueryRow(`SELECT timestamp, event_name, record_schema_version, bucket_catalog_version
				FROM audit_events`).Scan(&stamp, &event, &schema, &catalog); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				runtime.admission = router.AdmissionOrdinary
				if _, err := store.db.Exec(`UPDATE audit_events SET timestamp = ?, event_name = ?,
					record_schema_version = ?, bucket_catalog_version = ?`, stamp, event, schema, catalog); err != nil {
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
