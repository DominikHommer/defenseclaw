// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

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

// Review P2 (GAP-0352, loop round 2): when neither the ledger nor the hold
// takes a removal, the account's pending mark keeps it closed: the gateway
// denies every guarded call of the account and the hook takes no record as
// proof. A pass that still cannot write keeps the mark. Once storage is
// back, the next pass for the account (no new removal needed) records an
// account-wide removal and clears the mark, so the agent that was running
// when the hook was removed still gets no allow, and one started after the
// pass does.
func TestEnterpriseForeignHookRemovalKeepsTheAccountClosedUntilItIsRecorded(t *testing.T) {
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
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return errors.New("no space left on device") }
	enterpriseForeignHookSessionRoot = func() (string, bool) { return root, true }
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck = previousOwner, previousDirTrust, previousFileTrust
		enterpriseForeignHookRevokeSessionRecords, enterpriseForeignHookSessionRoot = previousRevoke, previousRoot
	})
	revocations := 0
	enterpriseForeignHookRevokeSessionRecords = func(identity string, connectors []string) error {
		revocations++
		if pending, err := enterprisepolicy.ForeignHookRemovalPending(root, identity); revocations == 1 && (err != nil || !pending) {
			t.Errorf("the mark must be set before the records are revoked: %v %v", pending, err)
		}
		return nil
	}
	pending := func(identity string) bool {
		t.Helper()
		got, err := enterprisepolicy.ForeignHookRemovalPending(root, identity)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	// The hold cannot be written either: a folder is in its place.
	holdPath, _ := enterprisepolicy.ForeignHookRemovalHoldPath(root, "1001")
	if err := os.MkdirAll(filepath.Join(holdPath, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if !pending("1001") || pending("1002") || revocations != 1 {
		t.Fatalf("only this account must be held (revocations %d): %s", revocations, stderr.String())
	}
	if !strings.Contains(stderr.String(), "denied until a later pass records the removal") {
		t.Fatalf("stderr %q", stderr.String())
	}

	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if !pending("1001") {
		t.Fatal("a pass that still cannot write must keep the mark")
	}
	if _, err := os.Lstat(ledgerPath); !os.IsNotExist(err) {
		t.Fatalf("no ledger can exist yet: %v", err)
	}

	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	if err := os.RemoveAll(holdPath); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if stderr.Len() != 0 || pending("1001") {
		t.Fatalf("a pass that records the removal must clear the mark: %q", stderr.String())
	}
	removals, err := loadEnterpriseForeignHookRemovals(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	var recorded *enterprisepolicy.ForeignHookRemoval
	for i := range removals {
		if removals[i].Identity == "1001" && removals[i].Connector == "copilot" && removals[i].Path == enterpriseForeignHookUnrecordedRemoval {
			recorded = &removals[i]
		}
	}
	if recorded == nil {
		t.Fatalf("the ledger must record the removal for the account: %+v", removals)
	}
	parts := strings.Split(recorded.Mark, ":")
	if len(parts) != 3 {
		t.Fatalf("mark %q", recorded.Mark)
	}
	clock, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	running := enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: parts[0] + ":" + parts[1] + ":4242:" + strconv.FormatInt(clock-1, 10)}
	if got := enterprisepolicy.ApplyForeignHookRemovals(enterprisepolicy.GuardDecision{}, running, removals, nil, time.Now()); !got.Deny {
		t.Fatalf("the agent that was running must stay denied: %+v", got)
	}
	started := running
	started.Process = parts[0] + ":" + parts[1] + ":4243:" + strconv.FormatInt(clock+1, 10)
	if got := enterprisepolicy.ApplyForeignHookRemovals(enterprisepolicy.GuardDecision{}, started, removals, nil, time.Now()); got.Deny {
		t.Fatalf("an agent started after the pass must be allowed: %+v", got)
	}

	// Nothing pending and nothing removed: the pass writes nothing.
	before, err := os.Stat(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if after, err := os.Stat(ledgerPath); err != nil || !os.SameFile(before, after) {
		t.Fatalf("a pass with nothing to record must not rewrite the ledger: %v", err)
	}
}
