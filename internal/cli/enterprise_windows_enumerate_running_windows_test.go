// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

func stubEnumerateRunningAgents(t *testing.T, processes []inventory.AgentProcess, processErr error, sids map[string]string) {
	t.Helper()
	previousProcesses, previousLookup := enterpriseWindowsEnumerateAgentProcesses, enterpriseWindowsEnumerateAccountSID
	t.Cleanup(func() {
		enterpriseWindowsEnumerateAgentProcesses, enterpriseWindowsEnumerateAccountSID = previousProcesses, previousLookup
	})
	enterpriseWindowsEnumerateAgentProcesses = func() ([]inventory.AgentProcess, error) { return processes, processErr }
	enterpriseWindowsEnumerateAccountSID = func(account string) string { return sids[account] }
	resetEnumerateKnownSIDs(t)
}

func resetEnumerateKnownSIDs(t *testing.T) {
	t.Helper()
	known := &enterpriseWindowsEnumerateKnownSIDs
	known.Lock()
	known.byAccount = map[string]string{}
	known.Unlock()
	t.Cleanup(func() {
		known.Lock()
		known.byAccount = map[string]string{}
		known.Unlock()
	})
}

// GAP-0226: the enumerator is told which agent sessions run, by account SID
// and connector, so a running agent no row enrolls is reported.
func TestEnterpriseWindowsEnumerateRunningAgentsBySID(t *testing.T) {
	const alice, bob = "S-1-12-1-3570884736-1162376387-1447295907-1452683434", "S-1-5-21-1-2-3-1001"
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{
		{PID: 10, Connector: "Codex", User: `AzureAD\EntraAlice`},
		{PID: 11, Connector: "codex", User: `azuread\entraalice`},
		{PID: 12, Connector: "claudecode", User: `DCLAB\bob`},
		{PID: 13, Connector: "codex", User: `DCLAB\gone`},
		{PID: 14, Connector: "codex", User: ""},
	}, nil, map[string]string{`AzureAD\EntraAlice`: alice, `DCLAB\bob`: bob})
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex", "claudecode"})
	if len(got) != 2 || got[alice]["codex"] != "codex (pid 10)" || got[bob]["claudecode"] != "claudecode (pid 12)" {
		t.Fatalf("running agents = %+v", got)
	}
	if len(unknown) != 1 || unknown[0].User != `DCLAB\gone` || unknown[0].Connector != "codex" || unknown[0].SID != "" ||
		unknown[0].Code != enterprisehooks.UnprotectedCodeAgentUnprotected || !strings.Contains(unknown[0].Reason, "codex (pid 13)") ||
		!strings.Contains(unknown[0].Reason, "could not be resolved") {
		t.Fatalf("owner-unknown agents = %+v", unknown)
	}

	stderr := new(bytes.Buffer)
	stubEnumerateRunningAgents(t, nil, errors.New("snapshot denied"), nil)
	if got, unknown := enterpriseWindowsEnumerateRunningAgents(stderr, []string{"codex"}); got != nil || unknown != nil || !strings.Contains(stderr.String(), "running agent sessions are unreadable") {
		t.Fatalf("unreadable sessions: %+v %+v, log %q", got, unknown, stderr.String())
	}
}

// A failed or timed-out SID lookup must not drop a running agent from the
// unprotected record: the account keeps the SID an earlier cycle resolved,
// and an account never resolved is reported with its owner unknown, for an
// enabled connector only.
func TestEnterpriseWindowsEnumerateRunningAgentLookupFailureFailsClosed(t *testing.T) {
	const alice = "S-1-12-1-3570884736-1162376387-1447295907-1452683434"
	processes := []inventory.AgentProcess{{PID: 10, Connector: "codex", User: `AzureAD\EntraAlice`}}
	stubEnumerateRunningAgents(t, processes, nil, map[string]string{`AzureAD\EntraAlice`: alice})
	if got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"}); got[alice]["codex"] != "codex (pid 10)" || len(unknown) != 0 {
		t.Fatalf("first cycle: %+v %+v", got, unknown)
	}
	// The domain controller stops answering: the cached SID keeps the row.
	enterpriseWindowsEnumerateAccountSID = func(string) string { return "" }
	if got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"}); got[alice]["codex"] != "codex (pid 10)" || len(unknown) != 0 {
		t.Fatalf("failed lookup dropped the running agent: %+v %+v", got, unknown)
	}

	// Never resolved: owner unknown, unprotected; a disabled connector's
	// agent is not reported.
	resetEnumerateKnownSIDs(t)
	enterpriseWindowsEnumerateAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{
			{PID: 10, Connector: "codex", User: `AzureAD\EntraAlice`},
			{PID: 11, Connector: "codex", User: `azuread\entraalice`},
			{PID: 12, Connector: "opencode", User: `AzureAD\EntraAlice`},
		}, nil
	}
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"})
	if len(got) != 0 || len(unknown) != 1 || unknown[0].User != `AzureAD\EntraAlice` || unknown[0].Connector != "codex" ||
		!strings.Contains(unknown[0].Message(), "codex for user AzureAD\\EntraAlice is not protected") {
		t.Fatalf("never-resolved account: %+v %+v", got, unknown)
	}
}

func TestEnterpriseWindowsEnumerateRunningAgentLookupIsBounded(t *testing.T) {
	previousTimeout := enterpriseWindowsEnumerateRunningLookupTimeout
	t.Cleanup(func() { enterpriseWindowsEnumerateRunningLookupTimeout = previousTimeout })
	enterpriseWindowsEnumerateRunningLookupTimeout = 20 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{{PID: 1, Connector: "codex", User: `DCLAB\slow`}}, nil, nil)
	enterpriseWindowsEnumerateAccountSID = func(string) string {
		<-release
		return "S-1-5-21-1-2-3-1009"
	}
	started := time.Now()
	if got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"}); len(got) != 0 || len(unknown) != 1 {
		t.Fatalf("a lookup that does not answer must name no SID and report the owner unknown: %+v %+v", got, unknown)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("lookup took %s, want the bounded timeout", elapsed)
	}
}

// The standalone cycle hands the running sessions to the enumerator; the
// Secure Client profile does not.
func TestEnterpriseWindowsEnumerateCyclePassesRunningAgents(t *testing.T) {
	const alice = "S-1-12-1-3570884736-1162376387-1447295907-1452683434"
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{{PID: 10, Connector: "codex", User: `AzureAD\EntraAlice`}}, nil, map[string]string{`AzureAD\EntraAlice`: alice})
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{})
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	previousCacheLoader := enterpriseWindowsEnumerateGroupCacheLoader
	previousCacheWriter := enterpriseWindowsEnumerateGroupCacheWriter
	previousRecordWriter := enterpriseWindowsEnumerateUnprotectedWriter
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
		enterpriseWindowsEnumerateGroupCacheLoader = previousCacheLoader
		enterpriseWindowsEnumerateGroupCacheWriter = previousCacheWriter
		enterpriseWindowsEnumerateUnprotectedWriter = previousRecordWriter
	})
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return cfg, nil }
	enterpriseWindowsEnumerateGroupCacheLoader = func(string) (*enterprisehooks.WindowsEnrollmentGroupCache, error) {
		return enterprisehooks.NewWindowsEnrollmentGroupCache(), nil
	}
	enterpriseWindowsEnumerateGroupCacheWriter = func(string, *enterprisehooks.WindowsEnrollmentGroupCache) (bool, error) { return false, nil }
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, nil }
	var published []enterprisehooks.UnprotectedAgent
	enterpriseWindowsEnumerateUnprotectedWriter = func(_ string, agents []enterprisehooks.UnprotectedAgent) (bool, error) {
		published = agents
		return true, nil
	}
	var seen enterprisehooks.EnumerateOptions
	enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		seen = opts
		if label := opts.RunningAgents[alice]["codex"]; label != "" && opts.ReportUnprotected != nil {
			opts.ReportUnprotected(enterprisehooks.UnprotectedAgent{User: "EntraAlice", SID: alice, Connector: "codex", Reason: label + " runs for this account"})
		}
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}, nil
	}
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), new(bytes.Buffer), manifest); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if seen.RunningAgents[alice]["codex"] != "codex (pid 10)" {
		t.Fatalf("running agents not passed: %+v", seen.RunningAgents)
	}
	if len(published) != 1 || published[0].Connector != "codex" || !strings.Contains(published[0].Reason, "codex (pid 10)") {
		t.Fatalf("published = %+v", published)
	}
}
