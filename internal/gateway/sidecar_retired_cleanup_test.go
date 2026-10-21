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

// until 1.1: a removed connector's cleanup that cannot finish is not
// forgotten. Delete with internal/gateway/connector/removed.go.

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const retiredOmnigentModule = "defenseclaw_omnigent_policy"

// stageUncleanableRetiredOmnigent leaves what an older release's OmniGent
// setup wrote, with a config.yaml its cleanup refuses to edit (a root merge
// key brings DefenseClaw's module in), and the connector's lock entry.
func stageUncleanableRetiredOmnigent(t *testing.T) (dataDir, configPath, modulePath string) {
	t.Helper()
	home := testenv.PrivateTempDir(t)
	restoreHome, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	dataDir = testenv.PrivateTempDir(t)
	configPath = filepath.Join(home, ".omnigent", "config.yaml")
	modulePath = filepath.Join(dataDir, "hooks", retiredOmnigentModule+".py")
	for path, body := range map[string]string{
		configPath: "x-base: &base\n  policy_modules: [" + retiredOmnigentModule + "]\n<<: *base\n",
		modulePath: "# defenseclaw-managed-policy v1\ndef defenseclaw_policy(event):\n    pass\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	retired, _ := connector.RetiredConnector("omnigent")
	entry := connector.NewHookContractLockEntry(connector.SetupOpts{DataDir: dataDir, HookFailMode: "closed", GuardrailMode: "action"}, retired, "1.0.3")
	if err := connector.SaveFreshHookContractLockEntry(dataDir, entry); err != nil {
		t.Fatalf("stage omnigent lock: %v", err)
	}
	return dataDir, configPath, modulePath
}

func requireRetiredOmnigentLock(t *testing.T, dataDir string) {
	t.Helper()
	if got := connector.LoadHookContractLockEntry(dataDir, "omnigent"); got.Connector == "" {
		t.Fatal("the omnigent lock entry was cleared before its cleanup finished")
	}
}

// Every boot path that meets a removed connector returns a cleanup it could
// not finish, keeps the lock entry and keeps the name for the next boot; once
// the agent's config can be cleaned, the retry finishes and clears the lock.
func TestRetiredConnectorCleanupFailureIsKeptForRetry(t *testing.T) {
	ctx := context.Background()
	registry := connector.NewDefaultRegistry()

	t.Run("direct", func(t *testing.T) {
		dataDir, configPath, modulePath := stageUncleanableRetiredOmnigent(t)
		err := retireOrDropUnregisteredConnector(ctx, registry, dataDir, "omnigent", "removed", nil)
		if err == nil || !strings.Contains(err.Error(), "omnigent") {
			t.Fatalf("retire = %v, want the cleanup failure", err)
		}
		requireRetiredOmnigentLock(t, dataDir)
		if _, err := os.Lstat(modulePath); err != nil {
			t.Fatalf("the policy module went while config.yaml still names it: %v", err)
		}
		if err := os.WriteFile(configPath, []byte("policy_modules: [corp]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := retireOrDropUnregisteredConnector(ctx, registry, dataDir, "omnigent", "removed", nil); err != nil {
			t.Fatalf("retry after the config was fixed: %v", err)
		}
		if got := connector.LoadHookContractLockEntry(dataDir, "omnigent"); got.Connector != "" {
			t.Fatalf("lock survived a clean retry: %+v", got)
		}
		if _, err := os.Lstat(modulePath); !os.IsNotExist(err) {
			t.Fatalf("the policy module survived a clean retry: %v", err)
		}
	})

	t.Run("removed from the roster", func(t *testing.T) {
		dataDir, _, _ := stageUncleanableRetiredOmnigent(t)
		failed, dropped := teardownRemovedConnectorsReport(registry, []string{"omnigent"}, nil, connector.SetupOpts{DataDir: dataDir}, ctx)
		if !reflect.DeepEqual(failed, []string{"omnigent"}) || len(dropped) != 0 {
			t.Fatalf("failed=%v dropped=%v, want omnigent kept for retry", failed, dropped)
		}
		requireRetiredOmnigentLock(t, dataDir)
	})

	t.Run("removed from the roster with rollback authority", func(t *testing.T) {
		dataDir, _, _ := stageUncleanableRetiredOmnigent(t)
		s := multiBootSidecar(t)
		s.cfg.DataDir = dataDir
		lockState, err := connector.CaptureHookContractLockSnapshot(dataDir)
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
		requireRetiredOmnigentLock(t, dataDir)
	})

	t.Run("lock only", func(t *testing.T) {
		dataDir, _, _ := stageUncleanableRetiredOmnigent(t)
		roster := []string{"codex"}
		if err := connector.SaveActiveConnectors(dataDir, roster); err != nil {
			t.Fatal(err)
		}
		err := reconcileOrphanedConnectorRegistrations(ctx, registry, dataDir, roster, orphanConnectorReconcileOps{
			resolveOpts: func(conn connector.Connector) (connector.SetupOpts, error) {
				return connector.SetupOpts{DataDir: dataDir}, nil
			},
			clearLock: connector.ClearHookContractLockEntry,
		})
		if err == nil || !strings.Contains(err.Error(), "omnigent") {
			t.Fatalf("reconcile = %v, want the cleanup failure", err)
		}
		requireRetiredOmnigentLock(t, dataDir)
		if got := connector.LoadActiveConnectors(dataDir); !reflect.DeepEqual(got, roster) {
			t.Fatalf("active roster = %v, want %v", got, roster)
		}
	})
}
