// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A managed hook whose process looks like Secure Client (neither the Unix
// standalone hook nor the Windows standalone binary) but whose host the
// strict Secure Client classifier did not verify (opts.SecureClient false)
// gets none of the Secure Client openings (#1163): a stopped gateway service
// and an unreadable Copilot answer stay closed in open mode too (owner rule
// 2026-10-20, main-sync review finding 5).
func TestUnverifiedSecureClientHostManagedHookStaysClosed(t *testing.T) {
	opts := Options{ManagedEnterprise: true, SecureClient: false}
	if got := managedPeerFailMode(opts, "open", errManagedGatewayNotRunning); got != "closed" {
		t.Fatalf("unverified host, stopped gateway: fail mode = %q, want closed", got)
	}
	opts.SecureClient = true
	if got := managedPeerFailMode(opts, "open", errManagedGatewayNotRunning); got != "open" {
		t.Fatalf("authenticated Secure Client, stopped gateway: fail mode = %q, want open", got)
	}
	if got := managedPeerFailMode(opts, "open", errManagedGatewayPeerUnverified); got != "closed" {
		t.Fatalf("authenticated Secure Client, unverified peer: fail mode = %q, want closed", got)
	}

	sp := specs["copilot"]
	for _, fail := range []func(Options) int{
		func(o Options) int { return failUnreachable(o, sp, "open", managedGatewayNotRunningReason) },
		func(o Options) int { return failResponse(o, sp, "open", "invalid JSON response") },
	} {
		home := t.TempDir()
		var stdout, stderr bytes.Buffer
		o := Options{Connector: "copilot", Event: "preToolUse", ManagedEnterprise: true, SecureClient: false,
			Home: home, Stdout: &stdout, Stderr: &stderr, Now: time.Now}
		if code := fail(o); code != 0 || !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
			t.Fatalf("unverified host Copilot: code=%d stdout=%q, want the managed deny", code, stdout.String())
		}
		failures, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
		if !strings.Contains(string(failures), `"outcome":"fail_closed"`) {
			t.Fatalf("unverified host Copilot logged %q, want fail_closed", failures)
		}
	}
}
