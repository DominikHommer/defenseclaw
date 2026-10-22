// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestConfigManagerRejectedCandidateIsInDurableAudit(t *testing.T) {
	for _, reason := range []string{"schema", "pinned-pack"} {
		t.Run(reason, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			raw := "config_version: 9\ndata_dir: " + dir + "\nguardrail: {mode: observe}\n"
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
				return errors.New("pinned pack digest mismatch: private-canary")
			})
			mgr.bindObservabilityV8(runtime)
			active, generation := mgr.Current(), mgr.gen.Load()
			candidate := strings.Replace(raw, "mode: observe", "mode: action", 1)
			if reason == "schema" {
				candidate = strings.Replace(candidate, "mode: action", "mode: action, block_at: SUPER", 1)
			}
			if err := os.WriteFile(path, []byte(candidate), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := mgr.Reload(t.Context(), "test"); err == nil {
				t.Fatal("invalid candidate accepted")
			}
			if !reflect.DeepEqual(mgr.Current(), active) || mgr.gen.Load() != generation {
				t.Fatal("rejection replaced the active policy")
			}
			db, err := sql.Open("sqlite", capture.store.DatabasePath())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE event_name = 'config.reload.rejected'").Scan(&count); err != nil || count != 1 {
				t.Fatalf("durable config.reload.rejected rows = %d, %v", count, err)
			}
		})
	}
}
