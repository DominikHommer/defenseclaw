// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestGuardianCommitsForeignHookRemovalUnderTheResponseFence(t *testing.T) {
	previousCfg := cfg
	previousOwner := enterpriseHookAuthorizationOwnershipSetter
	previousDirTrust := enterpriseHookAuthorizationDirTrustCheck
	previousFileTrust := enterpriseHookAuthorizationFileTrustCheck
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookAuthorizationOwnershipSetter = previousOwner
		enterpriseHookAuthorizationDirTrustCheck = previousDirTrust
		enterpriseHookAuthorizationFileTrustCheck = previousFileTrust
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	dataDir := t.TempDir()
	guardianDir := filepath.Join(dataDir, "guardian")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		t.Fatal(err)
	}
	fence := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFenceFile)
	before, err := os.Stat(fence)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := enterprisepolicy.LockForeignHookRemovals(context.Background(), fence)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		var stderr bytes.Buffer
		recordEnterpriseForeignHookRemovals(&stderr, "1001", "/home/alice", "claudecode", []string{"/home/alice/.claude/settings.json"})
		done <- stderr.String()
	}()
	ledger := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	select {
	case message := <-done:
		unlock()
		t.Fatalf("guardian passed the held response fence: %s", message)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(ledger); !os.IsNotExist(err) {
		unlock()
		t.Fatalf("guardian published before the response finished: %v", err)
	}
	unlock()
	select {
	case message := <-done:
		if message != "" {
			t.Fatal(message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("guardian did not commit after the response")
	}
	removals, err := loadEnterpriseForeignHookRemovals(ledger)
	if err != nil || len(removals) != 1 || removals[0].Identity != "1001" {
		t.Fatalf("committed removals = %+v, %v", removals, err)
	}
	after, err := os.Stat(fence)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the permanent response fence was replaced: %v", err)
	}
}
