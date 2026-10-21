// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// G-flood bench branch only: never merged.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// TestGFloodWALShape runs warm-up hook calls, empties the WAL, runs a measured
// window of calls with no checkpoint, and copies audit.db and its WAL to
// GFLOOD_SHAPE_OUT for offline frame analysis.
func TestGFloodWALShape(t *testing.T) {
	out := os.Getenv("GFLOOD_SHAPE_OUT")
	if out == "" {
		t.Skip("bench")
	}
	warm, _ := strconv.Atoi(os.Getenv("GFLOOD_SHAPE_WARM"))
	window, _ := strconv.Atoi(os.Getenv("GFLOOD_SHAPE_CALLS"))
	if window == 0 {
		window = 100
	}
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	cwd := t.TempDir()
	call := func(index int) {
		body, _ := json.Marshal(map[string]any{
			"session_id": "shape", "transcript_path": filepath.Join(cwd, "transcript.jsonl"), "cwd": cwd,
			"hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_use_id": fmt.Sprintf("toolu_%06d", index),
			"tool_input":  map[string]any{"command": "echo ok"},
		})
		recorder := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(recorder,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
	}
	ctx := context.Background()
	for index := range warm {
		call(index)
		if index%200 == 199 {
			_, _ = fixture.store.CheckpointWALIfLarge(ctx, 0, time.Second)
		}
	}
	for range 5 {
		result, err := fixture.store.CheckpointWALIfLarge(ctx, 0, time.Second)
		t.Logf("empty the log: %+v %v", result, err)
		if result.Truncated {
			break
		}
		time.Sleep(3 * time.Second)
	}
	for index := warm; index < warm+window; index++ {
		call(index)
	}
	copyFile := func(src, dst string) {
		in, err := os.Open(src)
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		outFile, err := os.Create(dst)
		if err != nil {
			t.Fatal(err)
		}
		defer outFile.Close()
		if _, err := io.Copy(outFile, in); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	copyFile(fixture.path, filepath.Join(out, "audit.db"))
	copyFile(fixture.path+"-wal", filepath.Join(out, "audit.db-wal"))
	t.Logf("copied %d calls after %d warm-up calls to %s", window, warm, out)
}
