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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// foreignHookRemovalTestGuardian is a standalone guardian whose ledger
// folder, protected session record root and data directory are temporary
// folders it trusts; the ledger folder fails its check while *ledgerErr is
// set. The record root has a generation file. Every bump of the record
// generation is reported to *bumped (when set) before it runs.
func foreignHookRemovalTestGuardian(t *testing.T, ledgerErr *error) (ledgerPath, root string) {
	t.Helper()
	guardianDir := filepath.Join(t.TempDir(), "guardian")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	root = t.TempDir()
	if err := enterprisepolicy.BumpPublishedSessionGeneration(root); err != nil {
		t.Fatal(err)
	}
	previousCfg := cfg
	previousOwner, previousDirTrust, previousFileTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck
	previousBump, previousRoot := enterpriseForeignHookBumpSessionGeneration, enterpriseForeignHookSessionRoot
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
		enterpriseForeignHookBumpSessionGeneration, enterpriseForeignHookSessionRoot = previousBump, previousRoot
	})
	return filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile), root
}

// withForeignHookRemovalBumps reports every bump of the record generation to
// before, which may refuse it, and then runs the real one.
func withForeignHookRemovalBumps(t *testing.T, before func(root string) error) {
	t.Helper()
	enterpriseForeignHookBumpSessionGeneration = func(root string) error {
		if err := before(root); err != nil {
			return err
		}
		return enterprisepolicy.BumpPublishedSessionGeneration(root)
	}
}

func foreignHookRemovalTestPending(t *testing.T, identity string) bool {
	t.Helper()
	got, err := enterprisepolicy.ForeignHookRemovalPending(cfg.DataDir, identity)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// foreignHookRemovalTestGeneration is the record generation under root, read
// the way the hook reads it.
func foreignHookRemovalTestGeneration(t *testing.T, root string) string {
	t.Helper()
	path, _ := enterprisepolicy.PublishedSessionGenerationPath(root)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.FormatInt(info.ModTime().UnixNano(), 10)
}

// foreignHookRemovalTestAllow writes a protected allow record of process
// for identity under root, as the gateway publishes one: stamped with the
// current generation.
func foreignHookRemovalTestAllow(t *testing.T, root, identity, process string) string {
	t.Helper()
	path := foreignHookRemovalTestPublish(t, root, identity, process)
	if !foreignHookRemovalTestProves(root, identity, process) {
		t.Fatal("a fresh allow of the current generation must prove the process")
	}
	return path
}

// foreignHookRemovalTestPublish writes the allow of
// foreignHookRemovalTestAllow without checking that it proves the process.
func foreignHookRemovalTestPublish(t *testing.T, root, identity, process string) string {
	t.Helper()
	path, ok := enterprisepolicy.PublishedSessionRecordPath(root, identity, "copilot", "p", process)
	if !ok {
		t.Fatal("no record path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(enterprisepolicy.PublishedSessionRecord{Version: 2, Connector: "copilot", Kind: "p", ID: process,
		At: time.Now().UTC().Format(time.RFC3339), Generation: foreignHookRemovalTestGeneration(t, root)})
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

// Lead directive (GAP-0352 review loop round 1): after the ledger names a
// removal, the guardian bumps the record generation instead of finding and
// revoking the account's records. Every allow written before the bump, of
// this account and any other, proves nothing after it, also one the account
// moved out of the record folder during the removal and brought back. The
// ledger already names the removal when the bump runs: an exchange that
// stamps its answer with the new generation read it. A ledger that cannot
// be written still bumps, and holds the account.
func TestEnterpriseForeignHookRemovalBumpsTheGenerationAfterTheLedger(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var bumps int
	withForeignHookRemovalBumps(t, func(string) error {
		bumps++
		if ledgerErr != nil {
			return nil
		}
		removals, err := loadEnterpriseForeignHookRemovals(ledgerPath)
		if err != nil {
			t.Errorf("the ledger must be readable when the generation is bumped: %v", err)
		}
		found := false
		for _, removal := range removals {
			found = found || (removal.Identity == "1001" && removal.Connector == "copilot" && removal.Path == hook)
		}
		if !found {
			t.Errorf("the ledger must name the removal before the generation is bumped: %+v", removals)
		}
		return nil
	})
	process := runtime.GOOS + ":b:1:100"
	mine := foreignHookRemovalTestAllow(t, root, "1001", process)
	foreignHookRemovalTestAllow(t, root, "1002", process)
	// The account moves its record folder away during the removal.
	aside := filepath.Join(t.TempDir(), "aside")
	if err := os.Rename(filepath.Dir(mine), aside); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if bumps != 1 || stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") {
		t.Fatalf("one bump, nothing held (bumps %d): %q", bumps, stderr.String())
	}
	if err := os.Rename(aside, filepath.Dir(mine)); err != nil {
		t.Fatal(err)
	}
	if foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatal("the allow brought back after the removal must prove nothing")
	}
	if foreignHookRemovalTestProves(root, "1002", process) {
		t.Fatal("every earlier allow must prove nothing after the bump")
	}

	ledgerErr = errors.New("the folder is writable by others")
	foreignHookRemovalTestAllow(t, root, "1001", process)
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if bumps != 2 || !foreignHookRemovalTestPending(t, "1001") || foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatalf("a ledger that cannot be written must still bump, and hold the account (bumps %d): %q", bumps, stderr.String())
	}
	for _, want := range []string{"record the copilot hook removal", "denied until a later pass records the removal"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr %q lacks %q", stderr.String(), want)
		}
	}
}

// Review P1 (GAP-0352, loop round 3): a removal the ledger cannot take holds
// the account closed with its pending mark, on its private session store in
// the gateway's data directory, set before the generation is bumped. Nothing
// is written into the record tree but the generation, and changing the tree
// does not clear the mark. A pass that still cannot write keeps the mark.
// Once the ledger can be written, the next pass for the account (no new
// removal needed) records an account-wide removal, bumps, and only then
// clears the mark, so the agent that was running when the hook was removed
// still gets no allow, and one started after the pass does.
func TestEnterpriseForeignHookRemovalKeepsTheAccountClosedUntilItIsRecorded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	ledgerErr := errors.New("no space left on device")
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	var heldAtBump []bool
	withForeignHookRemovalBumps(t, func(string) error {
		heldAtBump = append(heldAtBump, foreignHookRemovalTestPending(t, "1001"))
		return nil
	})
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if !foreignHookRemovalTestPending(t, "1001") || foreignHookRemovalTestPending(t, "1002") {
		t.Fatalf("only this account must be held: %s", stderr.String())
	}
	if len(heldAtBump) != 1 || !heldAtBump[0] {
		t.Fatalf("the mark must be set before the bump: %v", heldAtBump)
	}
	if !strings.Contains(stderr.String(), "denied until a later pass records the removal") {
		t.Fatalf("stderr %q", stderr.String())
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 1 || entries[0].Name() != enterprisepolicy.PublishedSessionGenerationFile {
		t.Fatalf("nothing but the generation may be in the record tree: %v %v", entries, err)
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
	heldAtBump = nil
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") {
		t.Fatalf("a pass that records the removal must clear the mark: %q", stderr.String())
	}
	if len(heldAtBump) != 1 || !heldAtBump[0] {
		t.Fatalf("the mark must be cleared only after the bump: %v", heldAtBump)
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

	// Nothing pending and nothing removed: the pass writes and bumps nothing.
	before, err := os.Stat(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	heldAtBump = nil
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if after, err := os.Stat(ledgerPath); err != nil || !os.SameFile(before, after) || len(heldAtBump) != 0 {
		t.Fatalf("a pass with nothing to record must not rewrite the ledger or bump: %v %v", err, heldAtBump)
	}
}

// Review P1 (GAP-0352, loop round 4; lead directive, loop round 1): a
// guardian that cannot locate the protected session record folder (a
// transient ProgramData lookup failure on Windows) cannot bump the record
// generation, so its removal holds the account closed: the gateway denies
// every guarded call of the account, and so publishes only blocks for it.
// While the lookup fails, passes keep the mark; the first pass that locates
// the folder records the account-wide removal, bumps, which ends the old
// allow, and only then clears the mark.
func TestEnterpriseForeignHookRemovalHoldsTheAccountWhileItsRecordFolderCannotBeLocated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	lookupErr := errors.New("SHGetKnownFolderPath(ProgramData): the RPC server is unavailable")
	enterpriseForeignHookSessionRoot = func() (string, error) {
		if lookupErr != nil {
			return "", lookupErr
		}
		return root, nil
	}
	var heldAtBump []bool
	withForeignHookRemovalBumps(t, func(string) error {
		heldAtBump = append(heldAtBump, foreignHookRemovalTestPending(t, "1001"))
		return nil
	})
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1001", process)
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if !foreignHookRemovalTestPending(t, "1001") || !strings.Contains(stderr.String(), "RPC server is unavailable") || len(heldAtBump) != 0 {
		t.Fatalf("a removal whose record folder cannot be located must hold the account (bumps %v): %q", heldAtBump, stderr.String())
	}
	key := enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: process}
	if got := enterprisepolicy.ApplyForeignHookRemovals(enterprisepolicy.GuardDecision{}, key, nil, enterprisepolicy.ErrForeignHookRemovalPending, time.Now()); !got.Deny {
		t.Fatalf("the gateway must deny the held account: %+v", got)
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
		t.Fatalf("once the folder is located the pass must clear the mark: %q", stderr.String())
	}
	if len(heldAtBump) != 1 || !heldAtBump[0] {
		t.Fatalf("the generation must be bumped before the mark is cleared: %v", heldAtBump)
	}
	if foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatal("the old allow must prove nothing once the mark is cleared")
	}
}

// Review P1 (GAP-0352, loop round 4; lead directive, loop round 1): a bump
// that fails (the record folder is missing, and may come back with its own
// old generation; the volume refuses the change) leaves the old allow
// standing for an outage, so it holds the account too, and only a pass
// whose bump succeeds clears the mark. A pending mark that cannot be read is
// held the same way: every pass bumps, and the mark is never cleared.
func TestEnterpriseForeignHookRemovalHoldsTheAccountUntilTheGenerationIsBumped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	_, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	bumpErr := errors.New("the record folder is missing")
	bumps := 0
	withForeignHookRemovalBumps(t, func(string) error {
		bumps++
		return bumpErr
	})
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1001", process)
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if !foreignHookRemovalTestPending(t, "1001") || !strings.Contains(stderr.String(), "until a later pass invalidates the protected session records") {
		t.Fatalf("a failed bump must hold the account: %q", stderr.String())
	}
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if !foreignHookRemovalTestPending(t, "1001") {
		t.Fatal("a pass whose bump still fails must keep the mark")
	}
	bumpErr = nil
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") || foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatalf("the pass that bumps clears the mark, and the old allow proves nothing: %q", stderr.String())
	}

	// A store that is not a folder: the mark cannot be read.
	store := enterprisepolicy.ForeignHookSessionStoreDir(cfg.DataDir, "1002")
	if err := os.MkdirAll(filepath.Dir(store), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreignHookRemovalTestAllow(t, root, "1002", process)
	bumps = 0
	for pass := 0; pass < 2; pass++ {
		stderr.Reset()
		recordEnterpriseForeignHookRemovals(&stderr, "1002", home, "copilot", nil)
	}
	if bumps != 2 || foreignHookRemovalTestProves(root, "1002", process) {
		t.Fatalf("an unreadable mark must bump on every pass (bumps %d): %q", bumps, stderr.String())
	}
	if info, err := os.Lstat(store); err != nil || info.IsDir() {
		t.Fatalf("an unreadable mark must never be cleared: %v %v", info, err)
	}
}

// Review P2 (GAP-0352, loop round 4; lead directive, loop round 1): the
// guardian holds an account whose removals the full ledger cannot keep
// before it writes the ledger, and the bump after the write ends that
// account's allows: a dropped denial never revives another account's old
// agent, online or during an outage.
func TestEnterpriseForeignHookRemovalHoldsAccountsTheFullLedgerDrops(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
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
	victim := ""
	for _, removal := range removals {
		victim = removal.Identity
	}
	var heldAtBump []bool
	withForeignHookRemovalBumps(t, func(string) error {
		heldAtBump = append(heldAtBump, foreignHookRemovalTestPending(t, victim))
		return nil
	})
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
	if len(heldAtBump) != 1 || !heldAtBump[0] {
		t.Fatalf("the dropped account must be held before the bump: %v", heldAtBump)
	}
	if foreignHookRemovalTestProves(root, victim, process) {
		t.Fatal("the dropped account's allow must prove nothing after the bump")
	}
	key := enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: process}
	if got := enterprisepolicy.ApplyForeignHookRemovals(enterprisepolicy.GuardDecision{}, key, nil, enterprisepolicy.ErrForeignHookRemovalPending, time.Now()); !got.Deny {
		t.Fatalf("the gateway must deny the dropped account online: %+v", got)
	}
}

// Review P1 and P2 (GAP-0352, 1.0.4 guard loop round 1): the guardian holds the
// records where the hook sees them before it publishes a removal, and
// releases them only after the bump. Between the ledger write and the bump
// the gateway denies from the new ledger, so the hook must not accept a
// fresh allow of the generation the bump is about to end, of this account
// or any other. A bump that fails keeps the hold: an allow the gateway wrote
// with the unchanged generation (before it read the mark) proves nothing
// during an outage, until a later pass bumps.
func TestEnterpriseForeignHookRemovalHoldsTheRecordsUntilTheBumpSucceeds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1001", process)
	foreignHookRemovalTestAllow(t, root, "1002", process)
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	bumpErr := errors.New("the volume refused the change")
	var checked int
	withForeignHookRemovalBumps(t, func(string) error {
		checked++
		removals, err := loadEnterpriseForeignHookRemovals(ledgerPath)
		if err != nil || len(removals) == 0 {
			t.Errorf("the ledger names the removal by the bump: %+v %v", removals, err)
		}
		if !enterprisepolicy.PublishedSessionHeld(root) {
			t.Error("the records must be held once the ledger is published, before the bump")
		}
		for _, identity := range []string{"1001", "1002"} {
			if foreignHookRemovalTestProves(root, identity, process) {
				t.Errorf("between the ledger and the bump the allow of %s must prove nothing", identity)
			}
		}
		return bumpErr
	})
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if checked != 1 || !foreignHookRemovalTestPending(t, "1001") {
		t.Fatalf("a failed bump holds the account (checks %d): %q", checked, stderr.String())
	}
	// The gateway answered before it read the mark: a fresh allow with the
	// generation the failed bump did not end.
	foreignHookRemovalTestPublish(t, root, "1001", process)
	foreignHookRemovalTestPublish(t, root, "1002", process)
	if !enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatal("a failed bump must leave the records held")
	}
	for _, identity := range []string{"1001", "1002"} {
		if foreignHookRemovalTestProves(root, identity, process) {
			t.Fatalf("after a failed bump the allow of %s must prove nothing during an outage", identity)
		}
	}
	bumpErr = nil
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if stderr.Len() != 0 || enterprisepolicy.PublishedSessionHeld(root) || foreignHookRemovalTestPending(t, "1001") {
		t.Fatalf("the pass that bumps releases the hold and the mark: %q", stderr.String())
	}
	for _, identity := range []string{"1001", "1002"} {
		if foreignHookRemovalTestProves(root, identity, process) {
			t.Fatalf("the bump ends the earlier allow of %s", identity)
		}
	}
	foreignHookRemovalTestAllow(t, root, "1002", process)
}

// Review P2 (GAP-0352, 1.0.4 guard loop round 1): a pass that stopped after it
// published the removal and before the bump (the guardian was stopped or
// crashed) left only its hold: no pending mark, and the next pass has no
// files to record. That pass still finishes the work: it records an
// account-wide removal, bumps and releases the hold, so the gap does not
// last until the record expires.
func TestEnterpriseForeignHookRemovalFinishesAnInterruptedPass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	bumps := 0
	withForeignHookRemovalBumps(t, func(string) error {
		bumps++
		return nil
	})
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1001", process)
	if err := enterprisepolicy.HoldPublishedSessionRemoval(root, "1001"); err != nil {
		t.Fatal(err)
	}
	if foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatal("the hold of the interrupted pass must keep the allow from proving anything")
	}
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", t.TempDir(), "copilot", nil)
	if bumps != 1 || stderr.Len() != 0 || enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatalf("the next pass bumps and releases the hold (bumps %d): %q", bumps, stderr.String())
	}
	removals, err := loadEnterpriseForeignHookRemovals(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	unrecorded := 0
	for _, removal := range removals {
		if removal.Identity == "1001" && removal.Path == enterpriseForeignHookUnrecordedRemoval {
			unrecorded++
		}
	}
	if unrecorded == 0 {
		t.Fatalf("the files of the interrupted pass are unknown: the account's removal covers every connector: %+v", removals)
	}
	if foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatal("the bump ends the earlier allow")
	}
	// No hold, no mark, no files: nothing to do.
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", t.TempDir(), "copilot", nil)
	if bumps != 1 {
		t.Fatalf("a pass with nothing to record must not bump: %d", bumps)
	}
}

// Review P2 (GAP-0352, 1.0.4 guard loop round 1): a hold another account's pass
// left (that account may never get another pass: it was removed) does not
// hold every account for ever. The next pass for any account holds that
// account closed in the gateway first, so nothing of it can be allowed
// again, then bumps and releases its hold. A hold that names no account
// stays and is reported.
func TestEnterpriseForeignHookRemovalEndsAHoldAnotherAccountLeft(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	_, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	var pendingAtBump []bool
	withForeignHookRemovalBumps(t, func(string) error {
		pendingAtBump = append(pendingAtBump, foreignHookRemovalTestPending(t, "1002"))
		return nil
	})
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1002", process)
	if err := enterprisepolicy.HoldPublishedSessionRemoval(root, "1002"); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", t.TempDir(), "copilot", nil)
	if stderr.Len() != 0 || enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatalf("the pass ends the other account's hold: %q", stderr.String())
	}
	if len(pendingAtBump) != 1 || !pendingAtBump[0] || !foreignHookRemovalTestPending(t, "1002") {
		t.Fatalf("the other account is held closed before the bump that ends its hold: %v", pendingAtBump)
	}
	if foreignHookRemovalTestProves(root, "1002", process) {
		t.Fatal("the bump ends the other account's earlier allow")
	}

	// A hold in the guardian's name that names no account.
	path, _ := enterprisepolicy.PublishedSessionRemovalHoldPath(root, "1003")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", t.TempDir(), "copilot", []string{filepath.Join(t.TempDir(), "x.json")})
	if !enterprisepolicy.PublishedSessionHeld(root) || !strings.Contains(stderr.String(), "names no account") {
		t.Fatalf("a hold that names no account stays and is reported: %q", stderr.String())
	}
}

// Review P1 (GAP-0352, 1.0.4 guard loop round 1): a guardian whose lookup of the
// standalone layout fails (on Windows, the protected ProgramData
// registration) finds the record folder from its data directory, so the
// removal still bumps the generation the hook reads, and the old allow
// proves nothing when the hook's own lookup works during an outage. Only
// when neither names the folder is the account held closed in the gateway
// alone.
func TestEnterpriseForeignHookRemovalFindsTheRecordFolderFromItsDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	locate := enterpriseForeignHookSessionRoot
	var ledgerErr error
	_, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	previousLayout, previousDataDir := enterpriseForeignHookSessionLayoutRoot, enterpriseForeignHookSessionRootForDataDir
	t.Cleanup(func() {
		enterpriseForeignHookSessionLayoutRoot, enterpriseForeignHookSessionRootForDataDir = previousLayout, previousDataDir
	})
	enterpriseForeignHookSessionRoot = locate
	enterpriseForeignHookSessionLayoutRoot = func() (string, error) {
		return "", errors.New("RegGetValue(ProgramData): the RPC server is unavailable")
	}
	enterpriseForeignHookSessionRootForDataDir = func(dataDir string) (string, bool) {
		return root, dataDir == cfg.DataDir
	}
	var bumped []string
	withForeignHookRemovalBumps(t, func(at string) error {
		bumped = append(bumped, at)
		return nil
	})
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1001", process)
	home := t.TempDir()
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{filepath.Join(home, ".copilot", "hooks", "x.json")})
	if stderr.Len() != 0 || len(bumped) != 1 || bumped[0] != root || foreignHookRemovalTestPending(t, "1001") || enterprisepolicy.PublishedSessionHeld(root) {
		t.Fatalf("the data directory names the record folder, which the pass bumps (bumped %v): %q", bumped, stderr.String())
	}
	if foreignHookRemovalTestProves(root, "1001", process) {
		t.Fatal("the old allow must prove nothing")
	}
	enterpriseForeignHookSessionRootForDataDir = func(string) (string, bool) { return "", false }
	stderr.Reset()
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{filepath.Join(home, ".copilot", "hooks", "y.json")})
	if len(bumped) != 1 || !foreignHookRemovalTestPending(t, "1001") || !strings.Contains(stderr.String(), "RPC server is unavailable") {
		t.Fatalf("with no folder named the account is held closed (bumped %v): %q", bumped, stderr.String())
	}
}
