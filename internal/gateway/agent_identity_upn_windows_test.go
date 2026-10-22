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
	if facts.ID == "" || facts.UserUPN != "ivan@corp.example.com" {
		t.Fatalf("agent identity %q recorded UPN %q, want ivan@corp.example.com", facts.ID, facts.UserUPN)
	}
}
