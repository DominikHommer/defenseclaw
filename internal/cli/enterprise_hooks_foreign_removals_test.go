// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Review P2 (GAP-0352): the guardian revokes an account's protected session
// records only after the removal ledger names the removal, so a gateway
// exchange that read the earlier ledger either sees the change (and
// withdraws its allow) or published before the revocation, which removes
// it. A ledger that cannot be written still revokes: revoking only blocks.
func TestEnterpriseForeignHookRemovalRevokesTheRecordsAfterTheLedger(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	guardianDir := filepath.Join(t.TempDir(), "guardian")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previousCfg := cfg
	previousOwner, previousDirTrust, previousFileTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck
	previousRevoke := enterpriseForeignHookRevokeSessionRecords
	cfg = &config.Config{
		DataDir:        t.TempDir(),
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck = previousOwner, previousDirTrust, previousFileTrust
		enterpriseForeignHookRevokeSessionRecords = previousRevoke
	})
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	ledgerPath := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	var revoked []string
	enterpriseForeignHookRevokeSessionRecords = func(identity string, connectors []string) error {
		removals, err := loadEnterpriseForeignHookRemovals(ledgerPath)
		if err != nil {
			t.Errorf("the ledger must be readable when the records are revoked: %v", err)
		}
		found := false
		for _, removal := range removals {
			found = found || (removal.Identity == identity && removal.Connector == "copilot" && removal.Path == hook)
		}
		if !found {
			t.Errorf("the ledger must name the removal before the records are revoked: %+v", removals)
		}
		revoked = append(revoked, identity+" "+strings.Join(connectors, ","))
		return nil
	}
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if len(revoked) != 1 || revoked[0] != "1001 copilot" || stderr.Len() != 0 {
		t.Fatalf("revoked %v, stderr %q", revoked, stderr.String())
	}

	revoked = nil
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return errors.New("the folder is writable by others") }
	enterpriseForeignHookRevokeSessionRecords = func(identity string, connectors []string) error {
		revoked = append(revoked, identity+" "+strings.Join(connectors, ","))
		return errors.New("a record could not be revoked")
	}
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if len(revoked) != 1 || revoked[0] != "1001 copilot" {
		t.Fatalf("a ledger that cannot be written must still revoke the records: %v", revoked)
	}
	for _, want := range []string{"record the copilot hook removal", "revoke the protected session records of 1001: a record could not be revoked"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr %q lacks %q", stderr.String(), want)
		}
	}
}
