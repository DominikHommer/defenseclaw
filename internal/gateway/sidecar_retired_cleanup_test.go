// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

// until 1.1: how boot treats a removed connector's cleanup. A cleanup that
// fails is kept and retried; one that leaves files for manual cleanup records
// the steps and never blocks the surviving connectors. Delete with
// internal/gateway/connector/removed.go.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const retiredOmnigentModule = "defenseclaw_omnigent_policy"

// writeRetiredSetupRecord writes the backup record an older release's setup
// left for path: the bytes it found (nil = none) and the bytes it wrote.
func writeRetiredSetupRecord(t *testing.T, dataDir, connectorName, logical, path string, found []byte, wrote string) {
	t.Helper()
	sum := func(data []byte) string {
		digest := sha256.Sum256(data)
		return hex.EncodeToString(digest[:])
	}
	record := map[string]any{
		"version":         1,
		"connector":       connectorName,
		"logical_name":    logical,
		"path":            path,
		"existed":         found != nil,
		"mode":            0o600,
		"pristine_sha256": "missing",
		"post_sha256":     sum([]byte(wrote)),
		"captured_at":     "2026-10-01T00:00:00Z",
	}
	if found != nil {
		record["pristine_sha256"] = sum(found)
		record["pristine_bytes"] = found
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeRetiredFile(t, filepath.Join(dataDir, "connector_backups", connectorName, logical+".json"), string(data))
	writeRetiredFile(t, path, wrote)
}

func writeRetiredFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

type retiredOmnigentHost struct {
	dataDir, configPath, modulePath, pthPath string
}

const (
	retiredOperatorConfig = "policy_modules: [corp_policy]\n"
	retiredPatchedConfig  = "policy_modules: [corp_policy, " + retiredOmnigentModule + "]\n" +
		"policies:\n  defenseclaw_guardrail:\n    handler: " + retiredOmnigentModule + ".defenseclaw_policy\n"
)

// stageRetiredOmnigent leaves what an older release's OmniGent setup wrote,
// with its backup records and the connector's lock entry.
func stageRetiredOmnigent(t *testing.T) retiredOmnigentHost {
	t.Helper()
	home := testenv.PrivateTempDir(t)
	restoreHome, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	h := retiredOmnigentHost{dataDir: testenv.PrivateTempDir(t)}
	h.configPath = filepath.Join(home, ".omnigent", "config.yaml")
	h.modulePath = filepath.Join(h.dataDir, "hooks", retiredOmnigentModule+".py")
	h.pthPath = filepath.Join(testenv.PrivateTempDir(t), "site-packages", "defenseclaw_omnigent.pth")
	writeRetiredSetupRecord(t, h.dataDir, "omnigent", "config", h.configPath, []byte(retiredOperatorConfig), retiredPatchedConfig)
	writeRetiredSetupRecord(t, h.dataDir, "omnigent", "pth", h.pthPath, nil, filepath.Dir(h.modulePath)+"\n")
	writeRetiredSetupRecord(t, h.dataDir, "omnigent", "module", h.modulePath, nil, "# defenseclaw-managed-policy v1\ndef defenseclaw_policy(event):\n    pass\n")
	retired, _ := connector.RetiredConnector("omnigent")
	entry := connector.NewHookContractLockEntry(connector.SetupOpts{DataDir: h.dataDir, HookFailMode: "closed", GuardrailMode: "action"}, retired, "1.0.3")
	if err := connector.SaveFreshHookContractLockEntry(h.dataDir, entry); err != nil {
		t.Fatalf("stage omnigent lock: %v", err)
	}
	return h
}

func (h retiredOmnigentHost) files(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, path := range []string{h.configPath, h.modulePath, h.pthPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			out[path] = "<missing>"
			continue
		}
		out[path] = string(data)
	}
	return out
}

func requireRetiredOmnigentLock(t *testing.T, dataDir string) {
	t.Helper()
	if got := connector.LoadHookContractLockEntry(dataDir, "omnigent"); got.Connector == "" {
		t.Fatal("the omnigent lock entry was cleared before its cleanup finished")
	}
}

// readOnlyRetiredConfig makes config.yaml's directory read-only, so the
// cleanup's first change fails.
func readOnlyRetiredConfig(t *testing.T, h retiredOmnigentHost) func() {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory modes do not stop writes here")
	}
	dir := filepath.Dir(h.configPath)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	restore := func() { _ = os.Chmod(dir, 0o700) }
	t.Cleanup(restore)
	return restore
}

// Every boot path that meets a removed connector whose cleanup fails returns
// the failure, keeps the lock entry and keeps the name for the next boot,
// with no file changed; once the cause is gone, the retry finishes.
func TestRetiredConnectorCleanupFailureIsKeptForRetry(t *testing.T) {
	ctx := context.Background()
	registry := connector.NewDefaultRegistry()

	t.Run("direct", func(t *testing.T) {
		h := stageRetiredOmnigent(t)
		before := h.files(t)
		restore := readOnlyRetiredConfig(t, h)
		err := retireOrDropUnregisteredConnector(ctx, registry, h.dataDir, "omnigent", "removed", nil)
		if err == nil || !strings.Contains(err.Error(), "omnigent") {
			t.Fatalf("retire = %v, want the cleanup failure", err)
		}
		requireRetiredOmnigentLock(t, h.dataDir)
		if got := h.files(t); !reflect.DeepEqual(got, before) {
			t.Fatalf("a failed cleanup changed files:\n got %v\nwant %v", got, before)
		}
		restore()
		if err := retireOrDropUnregisteredConnector(ctx, registry, h.dataDir, "omnigent", "removed", nil); err != nil {
			t.Fatalf("retry: %v", err)
		}
		if got := connector.LoadHookContractLockEntry(h.dataDir, "omnigent"); got.Connector != "" {
			t.Fatalf("lock survived a clean retry: %+v", got)
		}
		want := map[string]string{h.configPath: retiredOperatorConfig, h.modulePath: "<missing>", h.pthPath: "<missing>"}
		if got := h.files(t); !reflect.DeepEqual(got, want) {
			t.Fatalf("after the retry:\n got %v\nwant %v", got, want)
		}
	})

	t.Run("removed from the roster", func(t *testing.T) {
		h := stageRetiredOmnigent(t)
		readOnlyRetiredConfig(t, h)
		failed, dropped := teardownRemovedConnectorsReport(registry, []string{"omnigent"}, nil, connector.SetupOpts{DataDir: h.dataDir}, ctx)
		if !reflect.DeepEqual(failed, []string{"omnigent"}) || len(dropped) != 0 {
			t.Fatalf("failed=%v dropped=%v, want omnigent kept for retry", failed, dropped)
		}
		requireRetiredOmnigentLock(t, h.dataDir)
	})

	t.Run("removed from the roster with rollback authority", func(t *testing.T) {
		h := stageRetiredOmnigent(t)
		readOnlyRetiredConfig(t, h)
		s := multiBootSidecar(t)
		s.cfg.DataDir = h.dataDir
		lockState, err := connector.CaptureHookContractLockSnapshot(h.dataDir)
		if err != nil {
			t.Fatal(err)
		}
		candidates, unavailable := s.removedConnectorRollbackCandidates(
			registry, []string{"omnigent"}, []string{"codex"},
			"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key", lockState,
		)
		if len(candidates) != 0 || !reflect.DeepEqual(unavailable, []string{"omnigent"}) {
			t.Fatalf("candidates=%v unavailable=%v, want omnigent kept for retry", candidates, unavailable)
		}
		requireRetiredOmnigentLock(t, h.dataDir)
	})

	t.Run("lock only", func(t *testing.T) {
		h := stageRetiredOmnigent(t)
		readOnlyRetiredConfig(t, h)
		roster := []string{"codex"}
		if err := connector.SaveActiveConnectors(h.dataDir, roster); err != nil {
			t.Fatal(err)
		}
		err := reconcileOrphanedConnectorRegistrations(ctx, registry, h.dataDir, roster, orphanConnectorReconcileOps{
			resolveOpts: func(conn connector.Connector) (connector.SetupOpts, error) {
				return connector.SetupOpts{DataDir: h.dataDir}, nil
			},
			clearLock: connector.ClearHookContractLockEntry,
		})
		if err == nil || !strings.Contains(err.Error(), "omnigent") {
			t.Fatalf("reconcile = %v, want the cleanup failure", err)
		}
		requireRetiredOmnigentLock(t, h.dataDir)
		if got := connector.LoadActiveConnectors(h.dataDir); !reflect.DeepEqual(got, roster) {
			t.Fatalf("active roster = %v, want %v", got, roster)
		}
	})
}

// A removed connector whose files the user changed is left for manual
// cleanup: no file changes, the steps are recorded, and every boot path goes
// on with the surviving connectors (the name is dropped, not retried).
func TestRetiredConnectorManualCleanupDoesNotBlockSurvivors(t *testing.T) {
	ctx := context.Background()
	registry := connector.NewDefaultRegistry()
	stage := func(t *testing.T) (retiredOmnigentHost, map[string]string) {
		h := stageRetiredOmnigent(t)
		writeRetiredFile(t, h.configPath, retiredPatchedConfig+"model: local\n")
		return h, h.files(t)
	}
	requireLeft := func(t *testing.T, h retiredOmnigentHost, before map[string]string) {
		t.Helper()
		if got := h.files(t); !reflect.DeepEqual(got, before) {
			t.Fatalf("manual cleanup changed files:\n got %v\nwant %v", got, before)
		}
		data, err := os.ReadFile(filepath.Join(h.dataDir, "removed_connector_cleanup", "omnigent.json"))
		if err != nil || !strings.Contains(string(data), h.configPath) {
			t.Fatalf("manual cleanup record = %s, %v; want it to name %s", data, err, h.configPath)
		}
	}

	t.Run("direct", func(t *testing.T) {
		h, before := stage(t)
		if err := retireOrDropUnregisteredConnector(ctx, registry, h.dataDir, "omnigent", "removed", nil); err != nil {
			t.Fatalf("retire = %v, want the files left for manual cleanup", err)
		}
		requireLeft(t, h, before)
		if got := connector.LoadHookContractLockEntry(h.dataDir, "omnigent"); got.Connector != "" {
			t.Fatalf("lock kept for a connector left for manual cleanup: %+v", got)
		}
	})

	t.Run("removed from the roster", func(t *testing.T) {
		h, before := stage(t)
		failed, dropped := teardownRemovedConnectorsReport(registry, []string{"omnigent", "codex"}, []string{"codex"}, connector.SetupOpts{DataDir: h.dataDir}, ctx)
		if len(failed) != 0 || !reflect.DeepEqual(dropped, []string{"omnigent"}) {
			t.Fatalf("failed=%v dropped=%v, want omnigent dropped", failed, dropped)
		}
		requireLeft(t, h, before)
	})

	t.Run("single connector switch", func(t *testing.T) {
		h, before := stage(t)
		if err := connector.SaveActiveConnector(h.dataDir, "omnigent"); err != nil {
			t.Fatal(err)
		}
		if err := teardownPreviousConnector(registry, "codex", connector.SetupOpts{DataDir: h.dataDir}, ctx); err != nil {
			t.Fatalf("switch to codex = %v, want it to go on", err)
		}
		requireLeft(t, h, before)
	})
}
