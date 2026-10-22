// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// A FILE or DIR cache named by the user must belong to that user before its
// principal is used as a session claim.
func TestCredentialCacheFileRequiresEffectiveOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "krb5cc")
	if err := os.WriteFile(path, []byte{5, 4, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !regularFileOwnedByUID(info, os.Geteuid()) {
		t.Fatal("own regular cache was rejected")
	}
	if regularFileOwnedByUID(info, os.Geteuid()+1) {
		t.Fatal("another user cache was accepted")
	}
}

// GAP-0582: a credential cache on a mount that stopped answering costs one
// hook a short bound, not the whole session-facts deadline, and the hooks
// after it send the session variables alone without touching the cache.
func TestSessionFactsSkipAStalledCredentialCache(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KRB5CCNAME", "FILE:/stalled-mount/krb5cc")
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.1 22")
	t.Setenv("SSH_TTY", "")
	t.Setenv("XDG_SESSION_ID", "")
	var stats atomic.Int32
	previous := ccacheStat
	t.Cleanup(func() { ccacheStat = previous })
	// The stat never returns, like one on a stopped sshfs mount.
	ccacheStat = func(string) (os.FileInfo, error) {
		stats.Add(1)
		select {}
	}
	now := time.Now()
	for call := 1; call <= 2; call++ {
		started := time.Now()
		got := currentSessionFactsHeader(now)
		if elapsed := time.Since(started); elapsed >= 2*time.Second {
			t.Fatalf("call %d waited %v on the stalled credential cache", call, elapsed)
		}
		if got != "v1;k=ssh;ca=192.0.2.10" {
			t.Fatalf("call %d: header = %q, want the SSH facts alone", call, got)
		}
	}
	if n := stats.Load(); n != 1 {
		t.Fatalf("the credential cache was stat'ed %d times, want once", n)
	}
}
