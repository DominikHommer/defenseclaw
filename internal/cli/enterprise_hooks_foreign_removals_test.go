// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"io/fs"
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
// set. The record root has a key the test account made, which the test
// accepts as root's.
func foreignHookRemovalTestGuardian(t *testing.T, ledgerErr *error) (ledgerPath, root string) {
	t.Helper()
	guardianDir := filepath.Join(t.TempDir(), "guardian")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	root = filepath.Join(t.TempDir(), "sessions")
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal(err)
	}
	restoreOwner := enterprisepolicy.OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	if err := enterprisepolicy.CreatePublishedSessionKey(root, enterpriseForeignHookSessionKeyTrust()); err != nil {
		t.Fatal(err)
	}
	previousCfg := cfg
	previousOwner, previousDirTrust, previousFileTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck
	previousRoot, previousRetire, previousCreate, previousCan := enterpriseForeignHookSessionRoot, enterpriseForeignHookRetireSessionKey, enterpriseForeignHookCreateSessionKey, enterpriseForeignHookCanCreateSessionKey
	forgetRoot := func() {
		enterpriseForeignHookSessionRootSeen.Lock()
		enterpriseForeignHookSessionRootSeen.root = ""
		enterpriseForeignHookSessionRootSeen.Unlock()
	}
	forgetRoot()
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
		enterpriseForeignHookSessionRoot, enterpriseForeignHookRetireSessionKey, enterpriseForeignHookCreateSessionKey, enterpriseForeignHookCanCreateSessionKey = previousRoot, previousRetire, previousCreate, previousCan
		restoreOwner()
		forgetRoot()
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

func foreignHookRemovalTestKey(process string) enterprisepolicy.SessionKey {
	return enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: process}
}

// foreignHookRemovalTestAllow writes the protected allow records of
// process for identity under root, as the gateway publishes them: with the
// current key.
func foreignHookRemovalTestAllow(t *testing.T, root, identity, process string) {
	t.Helper()
	if err := enterprisepolicy.WritePublishedSessionRecordsForTest(root, identity, foreignHookRemovalTestKey(process), enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !foreignHookRemovalTestProves(root, identity, process) {
		t.Fatal("a fresh allow under the current key must prove the process")
	}
}

func foreignHookRemovalTestProves(root, identity, process string) bool {
	_, err := enterprisepolicy.CheckPublishedForeignHookSession(root, identity, foreignHookRemovalTestKey(process),
		enterprisepolicy.GuardDecision{}, func(string) error { return nil })
	return err == nil
}

// foreignHookRemovalTestEvents records the key removals, the ledger writes
// and the new keys of the guardian in order, and checks at each ledger write
// that no allow written before the pass proves anything where the hook
// reads it.
type foreignHookRemovalTestEvents struct {
	events []string
	// leftover is an allow that must prove nothing once a ledger is
	// written: root, identity, process.
	leftover []string
}

func withForeignHookRemovalEvents(t *testing.T, ledgerPath string) *foreignHookRemovalTestEvents {
	t.Helper()
	recorded := &foreignHookRemovalTestEvents{}
	previousRetire, previousCreate, previousOwner := enterpriseForeignHookRetireSessionKey, enterpriseForeignHookCreateSessionKey, enterpriseHookAuthorizationOwnershipSetter
	enterpriseForeignHookRetireSessionKey = func(root string, trust enterprisepolicy.PublishedSessionTrust) error {
		recorded.events = append(recorded.events, "kill")
		return previousRetire(root, trust)
	}
	enterpriseForeignHookCreateSessionKey = func(root string, trust enterprisepolicy.PublishedSessionTrust) error {
		recorded.events = append(recorded.events, "create")
		return previousCreate(root, trust)
	}
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		if path == ledgerPath {
			recorded.events = append(recorded.events, "ledger")
			if l := recorded.leftover; len(l) == 3 && foreignHookRemovalTestProves(l[0], l[1], l[2]) {
				t.Error("once the ledger is published the earlier allow must prove nothing where the hook reads it")
			}
		}
		return previousOwner(path)
	}
	return recorded
}

func (r *foreignHookRemovalTestEvents) String() string { return strings.Join(r.events, ",") }

// Kill switch (round 3 scenario 3; "no path publishes a removal before the
// rotation"): the guardian removes the protected session record key before
// it publishes anything (the ledger, a pending mark), and makes a new key
// only after every write, whatever fails:
//   - a removal: kill, ledger, new key;
//   - an account an earlier pass held: kill, the account-wide ledger entry,
//     new key, and only then the mark goes;
//   - a ledger that cannot be written: kill, the account is held, new key;
//   - a key that cannot be removed: a second key is added, which the hook
//     refuses; the account is held, and no new key resolves it;
//   - a record folder that cannot be located: the account is held, and
//     nothing else is done where the hook reads.
//
// At every ledger write, the allows written before the pass, of this
// account and another, prove nothing. After a pass that finished, a new
// allow proves its process again.
func TestEnterpriseForeignHookRemovalRemovesTheKeyBeforeItPublishes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	process := runtime.GOOS + ":b:1:100"
	stuck := errors.New("the file is in use")
	for _, tc := range []struct {
		name      string
		pending   bool
		ledgerErr error
		kill      func(root string) error
		rootErr   error
		paths     bool
		want      string
		held      bool
		proves    bool // a new allow proves its process after the pass
	}{
		{name: "a removal", paths: true, want: "kill,ledger,create", proves: true},
		{name: "an account an earlier pass held", pending: true, want: "kill,ledger,create", proves: true},
		{name: "a ledger that cannot be written", paths: true, ledgerErr: errors.New("no space left on device"), want: "kill,create", held: true, proves: true},
		{name: "a key that cannot be removed", paths: true, kill: func(root string) error {
			// The key stays, and a second one is added next to it.
			dir, _ := enterprisepolicy.PublishedSessionKeyDir(root)
			if err := os.WriteFile(filepath.Join(dir, filepath.Base(root)+enterprisepolicy.PublishedSessionKeyInfix+strings.Repeat("cd", 32)), nil, 0o644); err != nil {
				return err
			}
			return errors.Join(stuck, errors.New("a second key was added"))
		}, want: "kill,ledger", held: true},
		// The residual: with no folder named, nothing where the hook reads
		// changes (the hook resolves the same folder, and a lookup that keeps
		// failing blocks it too); the gateway denies the held account.
		{name: "a record folder that cannot be located", paths: true, rootErr: errors.New("SHGetKnownFolderPath(ProgramData): the RPC server is unavailable"), want: "ledger", held: true, proves: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledgerErr := tc.ledgerErr
			ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
			recorded := withForeignHookRemovalEvents(t, ledgerPath)
			if tc.kill != nil {
				enterpriseForeignHookRetireSessionKey = func(root string, _ enterprisepolicy.PublishedSessionTrust) error {
					recorded.events = append(recorded.events, "kill")
					return tc.kill(root)
				}
			}
			if tc.rootErr != nil {
				enterpriseForeignHookSessionRoot = func() (string, error) { return "", tc.rootErr }
			}
			if tc.pending {
				if err := enterprisepolicy.MarkForeignHookRemovalPending(cfg.DataDir, "1001"); err != nil {
					t.Fatal(err)
				}
			}
			foreignHookRemovalTestAllow(t, root, "1001", process)
			foreignHookRemovalTestAllow(t, root, "1002", process)
			if tc.rootErr == nil {
				recorded.leftover = []string{root, "1001", process}
			}
			home := t.TempDir()
			var paths []string
			if tc.paths {
				paths = []string{filepath.Join(home, ".copilot", "hooks", "x.json")}
			}
			var stderr bytes.Buffer
			recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", paths)
			if recorded.String() != tc.want {
				t.Fatalf("events %q, want %q: %s", recorded, tc.want, stderr.String())
			}
			if tc.rootErr == nil {
				for _, identity := range []string{"1001", "1002"} {
					if foreignHookRemovalTestProves(root, identity, process) {
						t.Fatalf("%s: every allow written before the pass must prove nothing after it", identity)
					}
				}
			}
			if got := foreignHookRemovalTestPending(t, "1001"); got != tc.held {
				t.Fatalf("held %v, want %v: %s", got, tc.held, stderr.String())
			}
			if tc.held != (stderr.Len() != 0) {
				t.Fatalf("a pass reports exactly what it could not do: %q", stderr.String())
			}
			foreignHookRemovalTestAllowAfter := func() bool {
				if err := enterprisepolicy.WritePublishedSessionRecordsForTest(root, "1002", foreignHookRemovalTestKey(process), enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
					t.Fatal(err)
				}
				return foreignHookRemovalTestProves(root, "1002", process)
			}
			if got := foreignHookRemovalTestAllowAfter(); got != tc.proves {
				t.Fatalf("a new allow proves %v, want %v", got, tc.proves)
			}
			if !tc.held {
				return
			}
			// The next pass that can do everything records the account,
			// makes one key and ends the hold.
			ledgerErr = nil
			enterpriseForeignHookSessionRoot = func() (string, error) { return root, nil }
			if tc.kill != nil {
				dir, _ := enterprisepolicy.PublishedSessionKeyDir(root)
				keys, _ := filepath.Glob(filepath.Join(dir, filepath.Base(root)+enterprisepolicy.PublishedSessionKeyInfix+"*"))
				if len(keys) != 2 {
					t.Fatalf("the stuck key and its second key must both be there: %v", keys)
				}
			}
			enterpriseForeignHookRetireSessionKey = enterprisepolicy.RetirePublishedSessionKey
			recorded = withForeignHookRemovalEvents(t, ledgerPath)
			stderr.Reset()
			recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
			if recorded.String() != "kill,ledger,create" || stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") {
				t.Fatalf("the next pass must finish (events %q): %q", recorded, stderr.String())
			}
			if !foreignHookRemovalTestAllowAfter() {
				t.Fatal("a new allow must prove its process after the pass that finished")
			}
		})
	}
}

// Review P1 (GAP-0352, loop round 3): a removal the ledger cannot take holds
// the account closed with its pending mark, on its private session store in
// the gateway's data directory, after the key was removed. Nothing is
// written into the record tree, and changing the tree does not clear the
// mark. A pass that still cannot write keeps the mark. Once the ledger can
// be written, the next pass for the account (no new removal needed)
// records an account-wide removal and only then clears the mark, so the
// agent that was running when the hook was removed still gets no allow, and
// one started after the pass does.
func TestEnterpriseForeignHookRemovalKeepsTheAccountClosedUntilItIsRecorded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	ledgerErr := errors.New("no space left on device")
	ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	home := t.TempDir()
	hook := filepath.Join(home, ".copilot", "hooks", "x.json")
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{hook})
	if !foreignHookRemovalTestPending(t, "1001") || foreignHookRemovalTestPending(t, "1002") {
		t.Fatalf("only this account must be held: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "denied until a later pass records the removal") {
		t.Fatalf("stderr %q", stderr.String())
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("nothing may be written into the record tree: %v %v", entries, err)
	}
	// An account that can change the record tree does not clear the mark.
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o711); err != nil {
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

	// Nothing pending and nothing removed: the pass writes and removes
	// nothing.
	before, err := os.Stat(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	recorded2 := withForeignHookRemovalEvents(t, ledgerPath)
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", nil)
	if after, err := os.Stat(ledgerPath); err != nil || !os.SameFile(before, after) || len(recorded2.events) != 0 {
		t.Fatalf("a pass with nothing to record must not rewrite the ledger or touch the key: %v %v", err, recorded2)
	}
}

// Kill switch: a new key that cannot be made after a removal leaves no key,
// so no outage allow proves anything until a later pass makes one; the
// account is not held for it (the removal is recorded) and the pass says
// so. A pending mark that cannot be read is held the same way at every
// pass: the key goes each time, and the mark is never cleared.
func TestEnterpriseForeignHookRemovalWithoutANewKeyBlocksEveryOutageAllow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	var ledgerErr error
	_, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	enterpriseForeignHookCreateSessionKey = func(string, enterprisepolicy.PublishedSessionTrust) error {
		return errors.New("no space left on device")
	}
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, "1002", process)
	home := t.TempDir()
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{filepath.Join(home, ".copilot", "hooks", "x.json")})
	if foreignHookRemovalTestPending(t, "1001") || !strings.Contains(stderr.String(), "guarded calls block during a gateway outage until a later pass makes one") {
		t.Fatalf("a key that cannot be made is reported, and the recorded removal holds nothing: %q", stderr.String())
	}
	if _, err := enterprisepolicy.ReadPublishedSessionKey(root); err == nil {
		t.Fatal("no key may be left")
	}
	if err := enterprisepolicy.WritePublishedSessionRecordsForTest(root, "1002", foreignHookRemovalTestKey(process), enterprisepolicy.GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if foreignHookRemovalTestProves(root, "1002", process) {
		t.Fatal("without a key no allow proves anything")
	}

	// A store that is not a folder: the mark cannot be read.
	enterpriseForeignHookCreateSessionKey = enterprisepolicy.CreatePublishedSessionKey
	store := enterprisepolicy.ForeignHookSessionStoreDir(cfg.DataDir, "1003")
	if err := os.MkdirAll(filepath.Dir(store), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	kills := 0
	enterpriseForeignHookRetireSessionKey = func(root string, trust enterprisepolicy.PublishedSessionTrust) error {
		kills++
		return enterprisepolicy.RetirePublishedSessionKey(root, trust)
	}
	for pass := 0; pass < 2; pass++ {
		stderr.Reset()
		recordEnterpriseForeignHookRemovals(&stderr, "1003", home, "copilot", nil)
	}
	if kills != 2 {
		t.Fatalf("an unreadable mark must remove the key at every pass (kills %d): %q", kills, stderr.String())
	}
	if info, err := os.Lstat(store); err != nil || info.IsDir() {
		t.Fatalf("an unreadable mark must never be cleared: %v %v", info, err)
	}
}

// Review P2 (GAP-0352, loop round 4): the guardian holds an account whose
// removals the full ledger cannot keep before it writes the ledger, and the
// key it removed before ends that account's allows: a dropped denial never
// revives another account's old agent, online or during an outage.
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
	process := runtime.GOOS + ":b:1:100"
	foreignHookRemovalTestAllow(t, root, victim, process)
	recorded := withForeignHookRemovalEvents(t, ledgerPath)
	recorded.leftover = []string{root, victim, process}
	heldAtLedger := false
	previousOwner := enterpriseHookAuthorizationOwnershipSetter
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		heldAtLedger = heldAtLedger || path == ledgerPath && foreignHookRemovalTestPending(t, victim)
		return previousOwner(path)
	}
	home := t.TempDir()
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{filepath.Join(home, ".copilot", "hooks", "y.json")})
	removals, err = loadEnterpriseForeignHookRemovals(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, removal := range removals {
		if removal.Identity == victim {
			t.Fatalf("the newest removal must push %s, the last horizon, out of the full ledger", victim)
		}
	}
	if !heldAtLedger || recorded.String() != "kill,ledger,create" {
		t.Fatalf("the dropped account must be held before the ledger is written (events %q): %q", recorded, stderr.String())
	}
	if foreignHookRemovalTestProves(root, victim, process) {
		t.Fatal("the dropped account's allow must prove nothing after the pass")
	}
	key := foreignHookRemovalTestKey(process)
	if got := enterprisepolicy.ApplyForeignHookRemovals(enterprisepolicy.GuardDecision{}, key, nil, enterprisepolicy.ErrForeignHookRemovalPending, time.Now()); !got.Deny {
		t.Fatalf("the gateway must deny the dropped account online: %+v", got)
	}
}

// Review P1 (GAP-0352, 1.0.4 guard loop rounds 1 and 3; round 3 scenario
// 1): a guardian whose lookup of the standalone layout fails (on Windows,
// the protected ProgramData registration) removes the key of the record
// folder it located last in this process, or else of the one its data
// directory names, so the old allow proves nothing when the hook's own
// lookup works during an outage. Only when neither names the folder is the
// account held closed in the gateway alone.
func TestEnterpriseForeignHookRemovalFindsTheRecordFolderWhenTheLookupFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
	for _, tc := range []struct {
		name    string
		located bool
	}{{"the folder it located last", true}, {"the folder its data directory names", false}} {
		t.Run(tc.name, func(t *testing.T) {
			locate := enterpriseForeignHookSessionRoot
			var ledgerErr error
			ledgerPath, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
			previousLayout, previousDataDir := enterpriseForeignHookSessionLayoutRoot, enterpriseForeignHookSessionRootForDataDir
			t.Cleanup(func() {
				enterpriseForeignHookSessionLayoutRoot, enterpriseForeignHookSessionRootForDataDir = previousLayout, previousDataDir
			})
			enterpriseForeignHookSessionRoot = locate
			var lookupErr error
			enterpriseForeignHookSessionLayoutRoot = func() (string, error) {
				if lookupErr != nil {
					return "", lookupErr
				}
				return root, nil
			}
			enterpriseForeignHookSessionRootForDataDir = func(dataDir string) (string, bool) {
				return root, !tc.located && dataDir == cfg.DataDir
			}
			home := t.TempDir()
			var stderr bytes.Buffer
			if tc.located {
				// The guardian service's pass (as SYSTEM) locates the folder.
				enterpriseForeignHookCanCreateSessionKey = func() bool { return true }
				ensureEnterpriseForeignHookSessionKey(&stderr)
			}
			process := runtime.GOOS + ":b:1:100"
			foreignHookRemovalTestAllow(t, root, "1001", process)
			lookupErr = errors.New("RegGetValue(ProgramData): the RPC server is unavailable")
			recorded := withForeignHookRemovalEvents(t, ledgerPath)
			recorded.leftover = []string{root, "1001", process}
			recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{filepath.Join(home, ".copilot", "hooks", "x.json")})
			if recorded.String() != "kill,ledger,create" || stderr.Len() != 0 || foreignHookRemovalTestPending(t, "1001") {
				t.Fatalf("the pass removes the key of the folder it found (events %q): %q", recorded, stderr.String())
			}
			if foreignHookRemovalTestProves(root, "1001", process) {
				t.Fatal("the old allow must prove nothing")
			}
		})
	}
	// Neither names the folder: the account is held closed.
	var ledgerErr error
	_, _ = foreignHookRemovalTestGuardian(t, &ledgerErr)
	enterpriseForeignHookSessionRoot = func() (string, error) { return "", errors.New("the RPC server is unavailable") }
	home := t.TempDir()
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "copilot", []string{filepath.Join(home, ".copilot", "hooks", "y.json")})
	if !foreignHookRemovalTestPending(t, "1001") || !strings.Contains(stderr.String(), "RPC server is unavailable") {
		t.Fatalf("with no folder named the account is held closed: %q", stderr.String())
	}
}

// Kill switch: every guardian pass that runs as root or SYSTEM makes a key
// when the record folder has none (the gateway removed it before a block,
// or a pass or lifecycle run did not finish), and keeps one that is there;
// any other account makes none.
func TestEnsureEnterpriseForeignHookSessionKeyAtEveryPass(t *testing.T) {
	var ledgerErr error
	_, root := foreignHookRemovalTestGuardian(t, &ledgerErr)
	key := func() string {
		k, err := enterprisepolicy.ReadPublishedSessionKey(root)
		if err != nil {
			return ""
		}
		return k.ID()
	}
	first := key()
	enterpriseForeignHookCanCreateSessionKey = func() bool { return true }
	var stderr bytes.Buffer
	ensureEnterpriseForeignHookSessionKey(&stderr)
	if key() != first || stderr.Len() != 0 {
		t.Fatalf("a key that is there must be kept: %q", stderr.String())
	}
	if err := enterprisepolicy.KillPublishedSessionKey(root); err != nil {
		t.Fatal(err)
	}
	enterpriseForeignHookCanCreateSessionKey = func() bool { return false }
	ensureEnterpriseForeignHookSessionKey(&stderr)
	if key() != "" {
		t.Fatal("an account that is not root or SYSTEM must make no key")
	}
	enterpriseForeignHookCanCreateSessionKey = func() bool { return true }
	ensureEnterpriseForeignHookSessionKey(&stderr)
	if next := key(); next == "" || next == first || stderr.Len() != 0 {
		t.Fatalf("a pass must make a new key when there is none: %q %q", next, stderr.String())
	}
}
