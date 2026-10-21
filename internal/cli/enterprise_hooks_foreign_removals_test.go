// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
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
	previousRoot := enterpriseForeignHookSessionRoot
	enterpriseForeignHookSessionRoot = func() (string, bool) { return "", false }
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
		enterpriseForeignHookSessionRoot = previousRoot
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

// Review P2 (GAP-0352): a removal the guardian cannot write to its ledger is
// held next to the account's protected session records before the records
// are revoked, so the gateway keeps denying the agent processes that
// started before it and publishes no allow for them. The next ledger write
// takes the held removal in, and then the hold goes.
func TestEnterpriseForeignHookRemovalHoldsWhatTheLedgerCannotTake(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	guardianDir := filepath.Join(t.TempDir(), "guardian")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	root := t.TempDir()
	previousCfg := cfg
	previousOwner, previousDirTrust, previousFileTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck
	previousRevoke, previousRoot := enterpriseForeignHookRevokeSessionRecords, enterpriseForeignHookSessionRoot
	cfg = &config.Config{
		DataDir:        t.TempDir(),
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return errors.New("the folder is writable by others") }
	enterpriseForeignHookSessionRoot = func() (string, bool) { return root, true }
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck = previousOwner, previousDirTrust, previousFileTrust
		enterpriseForeignHookRevokeSessionRecords, enterpriseForeignHookSessionRoot = previousRevoke, previousRoot
	})
	home := t.TempDir()
	first := filepath.Join(home, ".copilot", "hooks", "x.json")
	second := filepath.Join(home, ".copilot", "hooks", "y.json")
	ledgerPath := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	holdNames := func() []string {
		t.Helper()
		removals, _, err := enterprisepolicy.ReadForeignHookRemovalHold(root, "1001")
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		for _, removal := range removals {
			paths = append(paths, removal.Connector+" "+removal.Path)
		}
		return paths
	}
	revocations := 0
	enterpriseForeignHookRevokeSessionRecords = func(identity string, connectors []string) error {
		revocations++
		if revocations == 1 {
			if held := holdNames(); len(held) != 1 || held[0] != "copilot "+first {
				t.Errorf("the hold must name the removal before the records are revoked: %v", held)
			}
		}
		return nil
	}
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{first})
	if revocations != 1 || !strings.Contains(stderr.String(), "the gateway reads them from the account's hold") {
		t.Fatalf("revocations %d, stderr %q", revocations, stderr.String())
	}
	if _, err := os.Lstat(ledgerPath); !os.IsNotExist(err) {
		t.Fatalf("the ledger must not exist: %v", err)
	}
	holdPath, _ := enterprisepolicy.ForeignHookRemovalHoldPath(root, "1001")
	if info, err := os.Lstat(holdPath); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("the hold must be readable by the gateway only: %v %v", info, err)
	}

	// The ledger can be written again: it takes the held removal in, and
	// the hold goes.
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{second})
	if stderr.Len() != 0 {
		t.Fatalf("stderr %q", stderr.String())
	}
	removals, err := loadEnterpriseForeignHookRemovals(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, removal := range removals {
		found[removal.Path] = removal.Identity == "1001" && removal.Connector == "copilot"
	}
	if !found[first] || !found[second] {
		t.Fatalf("the ledger must hold the held and the new removal: %+v", removals)
	}
	if _, err := os.Lstat(holdPath); !os.IsNotExist(err) {
		t.Fatalf("the hold must go once the ledger holds its removals: %v", err)
	}
}
