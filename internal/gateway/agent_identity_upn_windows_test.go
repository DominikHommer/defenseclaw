// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// rel-1-0-4 GAP-0596: the agent identity of a verified SID records the UPN
// in the directory facts the hook path cached for that SID, as a Linux or
// macOS identity does for a uid, so enterprise windows agent-identities
// names it.
func TestAgentIdentityOfASIDRecordsTheCachedUPN(t *testing.T) {
	agentIdentityTestSetup(t)
	const sid = "S-1-5-21-1870-400-596-1105"
	peerDirectoryCache()
	previous := windowsDirectories
	windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Domain: "corp.example.com",
			UPN: "ivan@corp.example.com", ResolvedAt: time.Now(),
		}, nil
	})
	t.Cleanup(func() { windowsDirectories = previous })
	if _, ok := windowsDirectories.get(sid, true); !ok {
		t.Fatal("the hook path did not cache the SID's facts")
	}
	ctx := context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, strings.ToLower(sid))
	facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"})
	if facts.ID == "" || facts.UserUPN != "ivan@corp.example.com" || facts.UPNUnavailable {
		t.Fatalf("agent identity %q recorded UPN %q, want ivan@corp.example.com", facts.ID, facts.UserUPN)
	}

	// After a gateway restart an AD lookup can still be running. That is
	// distinct from a local account whose verified facts have no UPN.
	windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, ResolvedAt: time.Now()}, nil
	})
	if _, ok := windowsDirectories.get(sid, true); !ok {
		t.Fatal("the AD facts did not cache")
	}
	if cold := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"}); cold.UserUPN != "" || !cold.UPNUnavailable {
		t.Fatalf("cold AD UPN = %q, unavailable %t; want unavailable", cold.UserUPN, cold.UPNUnavailable)
	}
	windowsDirectories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, ResolvedAt: time.Now()}, nil
	})
	if _, ok := windowsDirectories.get(sid, true); !ok {
		t.Fatal("the local facts did not cache")
	}
	if local := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex"}); local.UserUPN != "" || local.UPNUnavailable {
		t.Fatalf("local UPN = %q, unavailable %t; want verified absence", local.UserUPN, local.UPNUnavailable)
	}
}
