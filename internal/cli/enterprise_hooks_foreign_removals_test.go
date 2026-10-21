// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	sessionRoot := t.TempDir()
	enterpriseForeignHookSessionRoot = func() (string, error) { return sessionRoot, nil }
	withForeignHookSessionTree(t, func(string) error { return nil })
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
	enterpriseForeignHookRevokeSessionRecords = func(_, identity string, connectors []string) error {
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
	enterpriseForeignHookRevokeSessionRecords = func(_, identity string, connectors []string) error {
		revoked = append(revoked, identity+" "+strings.Join(connectors, ","))
		return errors.New("a record could not be revoked")
	}
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if len(revoked) != 1 || !strings.HasPrefix(revoked[0], "1001 ") || !strings.Contains(revoked[0], "copilot") {
		t.Fatalf("a ledger that cannot be written must still revoke the records: %v", revoked)
	}
	for _, want := range []string{"record the copilot hook removal", "denied until a later pass records the removal",
		"revoke the protected session records of 1001: a record could not be revoked"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr %q lacks %q", stderr.String(), want)
		}
	}
}

// withForeignHookSessionTree replaces the guardian's check of the account's
// part of the protected session record tree.
func withForeignHookSessionTree(t *testing.T, problem func(string) error) {
	t.Helper()
	previous := enterpriseForeignHookSessionTreeProblem
	enterpriseForeignHookSessionTreeProblem = func(_, identity string) error { return problem(identity) }
	t.Cleanup(func() { enterpriseForeignHookSessionTreeProblem = previous })
}

// foreignHookRemovalTestGuardian is a standalone guardian whose ledger
// folder, protected session record root and data directory are temporary
// folders it trusts; the ledger folder fails its check while *ledgerErr is
// set.
func foreignHookRemovalTestGuardian(t *testing.T, ledgerErr *error) (ledgerPath, root string) {
	t.Helper()
	guardianDir := filepath.Join(t.TempDir(), "guardian")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	root = t.TempDir()
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
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return *ledgerErr }
	enterpriseForeignHookSessionRoot = func() (string, error) { return root, nil }
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck = previousOwner, previousDirTrust, previousFileTrust
		enterpriseForeignHookRevokeSessionRecords, enterpriseForeignHookSessionRoot = previousRevoke, previousRoot
	})
	return filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile), root
}

func foreignHookRemovalTestPending(t *testing.T, identity string) bool {
	t.Helper()
	got, err := enterprisepolicy.ForeignHookRemovalPending(cfg.DataDir, identity)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// foreignHookRemovalTestAllow writes a protected allow record of process
// for identity under root, as the gateway publishes one.
func foreignHookRemovalTestAllow(t *testing.T, root, identity, process string) string {
	t.Helper()
	path, ok := enterprisepolicy.PublishedSessionRecordPath(root, identity, "copilot", "p", process)
	if !ok {
		t.Fatal("no record path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(enterprisepolicy.PublishedSessionRecord{Version: 1, Connector: "copilot", Kind: "p", ID: process, At: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, record, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func foreignHookRemovalTestProves(root, identity, process string) bool {
	_, err := enterprisepolicy.CheckPublishedForeignHookSession(root, identity,
		enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: process}, enterprisepolicy.GuardDecision{}, func(string) error { return nil })
	return err == nil
}

// Review P1 (GAP-0352, loop round 3): a removal the ledger cannot take holds
// the account closed with its pending mark, on its private session store in
// the gateway's data directory. Nothing is left in the record tree, which
// an account could change while an administrator leaves it writable, and
// changing the tree does not clear the mark. The mark is set before the
// records are revoked, and every connector's records go. A pass that still
// cannot write keeps the mark. Once the ledger can be written, the next
// pass for the account (no new removal needed) records an account-wide
// removal and clears the mark, so the agent that was running when the hook
// was removed still gets no allow, and one started after the pass does.
func TestEnterpriseForeignHookRemovalKeepsTheAccountClosedUntilItIsRecorded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	ledgerErr := errors.New("no space left on device")
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	withForeignHookSessionTree(t, func(string) error { return nil })
	var revocations [][]string
	enterpriseForeignHookRevokeSessionRecords = func(_, identity string, connectors []string) error {
		if len(revocations) == 0 && !foreignHookRemovalTestPending(t, identity) {
			t.Error("the mark must be set before the records are revoked")
		}
		revocations = append(revocations, connectors)
		return nil
	}
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if !foreignHookRemovalTestPending(t, "1001") || foreignHookRemovalTestPending(t, "1002") || len(revocations) != 1 {
		t.Fatalf("only this account must be held (revocations %v): %s", revocations, stderr.String())
	}
	every := append(enterprisepolicy.StandaloneConnectors(cfg), "copilot")
	for _, name := range every {
		if !slices.Contains(revocations[0], name) {
			t.Fatalf("every connector's records of a held account must go: %v lacks %s", revocations[0], name)
		}
	}
	if !strings.Contains(stderr.String(), "denied until a later pass records the removal") {
		t.Fatalf("stderr %q", stderr.String())
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("nothing may be left in the record tree: %v %v", entries, err)
	}
	// An account that can change the record tree does not clear the mark.
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if !foreignHookRemovalTestPending(t, "1001") {
		t.Fatal("the mark must not live in the record tree")
	}

	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if !foreignHookRemovalTestPending(t, "1001") {
		t.Fatal("a pass that still cannot write must keep the mark")
	}
	if _, err := os.Lstat(ledgerPath); !os.IsNotExist(err) {
		t.Fatalf("no ledger can exist yet: %v", err)
	}

	ledgerErr = nil
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") {
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

// Review P1 (GAP-0352, loop round 3): the guardian trusts its revocation of
// an account's records only in a tree the hook trusts. While the record
// root let another account change it, that account moved its folder away,
// so the revocation found nothing, and it can bring the folder back before
// the access is put back. The ledger still names the removal, and the
// account is held closed while the tree stays one the hook refuses. Once
// the tree is trusted again, the next pass records an account-wide removal,
// revokes the folder that came back and clears the mark.
func TestEnterpriseForeignHookRemovalHoldsTheAccountWhileItsRecordsCanBeChanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	problem := errors.New("the record root is writable by another account")
	withForeignHookSessionTree(t, func(string) error { return problem })
	process := runtime.GOOS + ":b:1:100"
	record := foreignHookRemovalTestAllow(t, root, "1001", process)
	if !foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatal("the allow must prove the process before the removal")
	}
	account := filepath.Dir(record)
	aside := filepath.Join(t.TempDir(), "aside")
	if err := os.Rename(account, aside); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if !foreignHookRemovalTestPending(t, "1001") || !strings.Contains(stderr.String(), "another account could change") {
		t.Fatalf("a revocation in a tree another account could change must hold the account: %q", stderr.String())
	}
	removals, err := loadEnterpriseForeignHookRemovals(ledgerPath)
	if err != nil || len(removals) != 1 || removals[0].Path != hook {
		t.Fatalf("the ledger must still name the removal: %+v %v", removals, err)
	}
	before, err := os.Stat(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if !foreignHookRemovalTestPending(t, "1001") {
		t.Fatal("the account must stay held while the tree is one the hook refuses")
	}
	if after, err := os.Stat(ledgerPath); err != nil || !os.SameFile(before, after) {
		t.Fatalf("a held account is recorded only in a tree the hook trusts: %v", err)
	}
	// The account brings its folder back, and the access is put back.
	if err := os.Rename(aside, account); err != nil {
		t.Fatal(err)
	}
	problem = nil
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") {
		t.Fatalf("once the tree is trusted the pass must record the removal and clear the mark: %q", stderr.String())
	}
	if foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatal("the allow the account brought back must be revoked")
	}
	removals, err = loadEnterpriseForeignHookRemovals(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, removal := range removals {
		found = found || removal.Identity == "1001" && removal.Path == enterpriseForeignHookUnrecordedRemoval
	}
	if !found {
		t.Fatalf("the ledger must record the account-wide removal: %+v", removals)
	}
}

// Review P1 (GAP-0352, loop round 4): a guardian that cannot locate the
// protected session record folder (a transient ProgramData lookup failure
// on Windows) can neither check nor revoke the account's records, so its
// removal holds the account closed. Before, the tree check and the
// revocation both returned nil: the ledger took the removal, nothing held
// the account, and once the lookup recovered an outage hook accepted the
// old allow. While the lookup fails, passes keep the mark; the first pass
// that locates a trusted folder records the account-wide removal, revokes
// the old allow and clears the mark.
func TestEnterpriseForeignHookRemovalHoldsTheAccountWhileItsRecordFolderCannotBeLocated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	withForeignHookSessionTree(t, func(string) error { return nil })
	lookupErr := errors.New("SHGetKnownFolderPath(ProgramData): the RPC server is unavailable")
	enterpriseForeignHookSessionRoot = func() (string, error) {
		if lookupErr != nil {
			return "", lookupErr
		}
		return root, nil
	}
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1001", process)
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if !foreignHookRemovalTestPending(t, "1001") || !strings.Contains(stderr.String(), "cannot locate") {
		t.Fatalf("a removal whose record folder cannot be located must hold the account: %q", stderr.String())
	}
	removals, err := loadEnterpriseForeignHookRemovals(ledgerPath)
	if err != nil || len(removals) != 1 || removals[0].Path != hook {
		t.Fatalf("the ledger must still name the removal: %+v %v", removals, err)
	}
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if !foreignHookRemovalTestPending(t, "1001") {
		t.Fatal("a pass that still cannot locate the folder must keep the mark")
	}
	lookupErr = nil
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") {
		t.Fatalf("once the folder is located and trusted the pass must clear the mark: %q", stderr.String())
	}
	if foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatal("the old allow must be revoked before the mark is cleared")
	}
}

// Review P1 (GAP-0352, loop round 4), the recovery variant: an account
// already held (its ledger write failed) is not released by a pass that
// cannot locate the record folder. Before, that pass wrote the account-wide
// removal and cleared the mark without revoking the record, which an outage
// hook then accepted.
func TestEnterpriseForeignHookRemovalKeepsTheMarkWhileTheRecordFolderCannotBeLocated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	_, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	withForeignHookSessionTree(t, func(string) error { return nil })
	lookupErr := errors.New("the ProgramData lookup failed")
	enterpriseForeignHookSessionRoot = func() (string, error) {
		if lookupErr != nil {
			return "", lookupErr
		}
		return root, nil
	}
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1001", process)
	if err := enterprisepolicy.MarkForeignHookRemovalPending(cfg.DataDir, "1001"); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", t.TempDir(), "copilot", nil)
	if !foreignHookRemovalTestPending(t, "1001") {
		t.Fatalf("a pass that cannot locate the record folder must keep the mark: %q", stderr.String())
	}
	if !foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatal("nothing could be revoked in a folder that was not located")
	}
	if err := enterprisepolicy.ClearForeignHookRemovalPending(cfg.DataDir, "", "1001"); err == nil || !foreignHookRemovalTestPending(t, "1001") {
		t.Fatalf("a clear without a record folder must keep the mark: %v", err)
	}
	lookupErr = nil
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", t.TempDir(), "copilot", nil)
	if stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") || foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatalf("the pass that locates the folder revokes the allow and clears the mark: %q", stderr.String())
	}
}

// Review P1 (GAP-0352, loop round 4), the same class: a revocation that
// fails leaves the old allow standing for an outage, so it holds the
// account too, and only a pass whose revocation succeeds clears the mark.
// A pending mark that cannot be read is held the same way and never
// cleared.
func TestEnterpriseForeignHookRemovalHoldsTheAccountUntilItsRecordsAreRevoked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	_, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	withForeignHookSessionTree(t, func(string) error { return nil })
	revokeErr := errors.New("the record is held open")
	var revocations [][]string
	enterpriseForeignHookRevokeSessionRecords = func(root, identity string, connectors []string) error {
		revocations = append(revocations, connectors)
		if revokeErr != nil {
			return revokeErr
		}
		return enterprisepolicy.RemovePublishedForeignHookSessions(root, identity, connectors)
	}
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1001", process)
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if !foreignHookRemovalTestPending(t, "1001") || !strings.Contains(stderr.String(), "until a later pass revokes its records") {
		t.Fatalf("a failed revocation must hold the account: %q", stderr.String())
	}
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if !foreignHookRemovalTestPending(t, "1001") {
		t.Fatal("a pass whose revocation still fails must keep the mark")
	}
	revokeErr = nil
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") || foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatalf("the pass that revokes the records clears the mark: %q", stderr.String())
	}

	// A store that is not a folder: the mark cannot be read.
	store := enterprisepolicy.ForeignHookSessionStoreDir(cfg.DataDir, "1002")
	if err := os.MkdirAll(filepath.Dir(store), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	revocations = nil
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1002", home, "copilot", nil)
	every := append(enterprisepolicy.StandaloneConnectors(cfg), "copilot")
	if len(revocations) != 1 {
		t.Fatalf("an unreadable mark must revoke the account's records on every pass: %v %q", revocations, stderr.String())
	}
	for _, name := range every {
		if !slices.Contains(revocations[0], name) {
			t.Fatalf("an unreadable mark must revoke every connector's records: %v lacks %s", revocations[0], name)
		}
	}
	if info, err := os.Lstat(store); err != nil || info.IsDir() {
		t.Fatalf("an unreadable mark must never be cleared: %v %v", info, err)
	}
}

// Review P2 (GAP-0352, loop round 4): the guardian holds an account whose
// removals the full ledger cannot keep before it writes the ledger, and
// revokes its records after: a dropped denial never turns into an allow.
func TestEnterpriseForeignHookRemovalHoldsAccountsTheFullLedgerDrops(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	withForeignHookSessionTree(t, func(string) error { return nil })
	earlier := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	var existing []enterprisepolicy.ForeignHookRemoval
	for i := 0; i < 1100; i++ {
		existing = append(existing, enterprisepolicy.ForeignHookRemoval{Identity: strconv.Itoa(2000 + i), Connector: "copilot",
			Path: "/home/u/.copilot/hooks/x.json", At: earlier, Mark: runtime.GOOS + ":b:900"})
	}
	data, evicted, err := enterprisepolicy.EncodeForeignHookRemovals(nil, existing, time.Now())
	if err != nil || len(evicted) == 0 {
		t.Fatalf("the seeded ledger must already drop accounts: %v %v", evicted, err)
	}
	if err := os.MkdirAll(filepath.Dir(ledgerPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledgerPath, data, 0o640); err != nil {
		t.Fatal(err)
	}
	removals, err := loadEnterpriseForeignHookRemovals(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, removal := range removals {
		kept[removal.Identity] = true
	}
	victim := ""
	for _, removal := range removals {
		victim = removal.Identity
	}
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, victim, process)
	home := t.TempDir()
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{filepath.Join(home, ".copilot", "hooks", "y.json")})
	removals, err = loadEnterpriseForeignHookRemovals(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	still := false
	for _, removal := range removals {
		still = still || removal.Identity == victim
	}
	if still {
		t.Fatalf("the newest removal must push %s, the last horizon, out of the full ledger", victim)
	}
	if !foreignHookRemovalTestPending(t, victim) {
		t.Fatalf("an account whose denial the full ledger dropped must be held: %q", stderr.String())
	}
	if foreignHookRemovalTestProves(root, victim, process) {
		t.Fatal("the dropped account's allow must be revoked")
	}
}
