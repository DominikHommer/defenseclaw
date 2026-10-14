//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

type fixup2CodexCase struct {
	fixture               *standaloneFixture
	resolver              standaloneTestResolver
	entry                 enterpriseHookUserCleanup
	oldHome, currentHome  string
	currentConfig, seed   string
	workerRemoveResponses []enterpriseHookWorkerTargetResult
}

func setupFixup2CodexCase(t *testing.T, seed string, move bool) *fixup2CodexCase {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the per-user worker requires a non-root test account")
	}
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	oldHome := f.home(t, "sample-codex-old", 0o700)
	currentHome := f.home(t, "sample-codex-current", 0o700)
	t.Setenv("HOME", oldHome)
	t.Setenv("CODEX_HOME", "")
	previousPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = ""
	t.Cleanup(func() { connector.CodexConfigPathOverride = previousPath })
	oldConfig := filepath.Join(oldHome, ".codex", "config.toml")
	if seed != "" {
		if err := os.MkdirAll(filepath.Dir(oldConfig), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(oldConfig, []byte(seed), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if _, err := os.Stat(oldConfig); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap precondition failed: %v", err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "codex", UserHome: oldHome, OwnerUID: uid, OwnerGID: gid,
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "codex-cli 0.142.0",
		Registry: connector.NewDefaultRegistry(),
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("install Codex: %v", err)
	}
	copyRehomedTestTree(t, oldHome, currentHome)
	if move {
		if err := os.RemoveAll(oldHome); err != nil {
			t.Fatal(err)
		}
	}
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: currentHome}
	c := &fixup2CodexCase{fixture: f, resolver: resolver, oldHome: oldHome, currentHome: currentHome,
		currentConfig: filepath.Join(currentHome, ".codex", "config.toml"), seed: seed,
		entry: enterpriseHookUserCleanup{Connector: "codex", User: "sample-user", UID: uid,
			UserHome: oldHome, DataDir: filepath.Join(oldHome, ".defenseclaw")},
	}
	useEnterpriseHookWorkerHelper(t, "real")
	previousRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = previousRunner })
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response, err := runEnterpriseHookWorker(ctx, account, request)
		if err == nil {
			for _, result := range response.Targets {
				c.workerRemoveResponses = append(c.workerRemoveResponses, result)
			}
		}
		return response, err
	}
	return c
}

func TestStandaloneCleanupMovedCodexBootstrapAndTrustedProjects(t *testing.T) {
	for _, tc := range []struct{ name, seed string }{
		{name: "bootstrap stub"},
		{name: "uppercase project", seed: "[projects.\"/srv/work/DefenseClaw\"]\ntrust_level = \"trusted\"\n"},
		{name: "lowercase project", seed: "[projects.\"/home/sample-user/code/defenseclaw\"]\ntrust_level = \"trusted\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := setupFixup2CodexCase(t, tc.seed, true)
			for attempt := 1; attempt <= 2; attempt++ {
				outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, c.entry, c.resolver)
				if outcome != enterpriseHookUserCleanupDone || err != nil {
					t.Fatalf("attempt %d = %v, %v", attempt, outcome, err)
				}
			}
			data, err := os.ReadFile(c.currentConfig)
			if err != nil {
				t.Fatal(err)
			}
			if tc.seed == "" {
				for _, line := range []string{"# Created by DefenseClaw installer", "# repair this file. Edit freely; DefenseClaw only owns [hooks], [otel],", "# and the top-level notify entries."} {
					if !bytes.Contains(data, []byte(line)) {
						t.Fatalf("bootstrap header was lost: %q", data)
					}
				}
			} else if !bytes.Contains(data, []byte(tc.seed)) {
				t.Fatalf("trusted project changed: %q", data)
			}
			for _, result := range c.workerRemoveResponses {
				if !result.OK || !result.PathsReported || result.Remaining != "" {
					t.Fatalf("Codex Remove did not report clean: %+v", result)
				}
			}
			if len(c.workerRemoveResponses) != 2 {
				t.Fatalf("Remove responses = %d, want two", len(c.workerRemoveResponses))
			}
			if tc.seed == "" {
				now := time.Now()
				if err := saveEnterpriseHookUserCleanups(c.fixture.dataDir, []enterpriseHookUserCleanup{c.entry}, now); err != nil {
					t.Fatal(err)
				}
				c.fixture.writeManifest(t)
				manifest, err := enterprisehooks.LoadManifest(c.fixture.manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &bytes.Buffer{}, manifest,
					enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, c.resolver, now); err != nil {
					t.Fatal(err)
				}
				cmd := &cobra.Command{}
				cmd.SetContext(context.Background())
				report := enterpriseHooksRemoveAllReport{}
				runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
				if report.Removed != 0 || len(report.Failed) != 0 || len(report.Pending) != 0 {
					t.Fatalf("remove-all listed a completed Codex row: %+v", report)
				}
			}
		})
	}
}
