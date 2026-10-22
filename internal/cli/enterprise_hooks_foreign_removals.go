// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseForeignHookRemovalsMu serializes ledger updates: the Unix
// per-user workers report their removals concurrently.
var enterpriseForeignHookRemovalsMu sync.Mutex

// enterpriseForeignHookAccountID names an account the way the gateway names
// a verified caller: the SID when there is one, else the uid.
func enterpriseForeignHookAccountID(sid string, uid int) string {
	if sid != "" {
		return sid
	}
	if uid >= 0 {
		return strconv.Itoa(uid)
	}
	return ""
}

// recordEnterpriseForeignHookRemovals adds the hook files the guardian just
// cleaned for one account (home) and connector to the removal ledger the
// gateway reads (enterprisepolicy.ForeignHookRemovalsFile), so that
// account's agent processes of that connector, and of any other that loads
// the same file, that started before now stay denied: they may still run a
// hook they loaded. It runs after the files were cleaned, so every process
// that could have loaded one started before the recorded time.
//
// The kill switch (GAP-0352, 1.0.4 guard loop): before it publishes
// anything (the ledger, or any account's pending mark) it removes the key
// of the protected session records (enterprisepolicy.RetirePublishedSessionKey),
// so that no allow the gateway wrote before proves anything during an
// outage, of any account. Only after every write it makes a new key
// (enterprisepolicy.CreatePublishedSessionKey). The gateway reads the key
// before the ledger, so an allow made with the new key was decided from
// this ledger, and one made with the removed key, or with none, proves
// nothing. A pass that stops before the new key leaves none, which blocks
// every outage allow until the next pass makes one
// (ensureEnterpriseForeignHookSessionKey). No record has to be found or
// revoked, so no account can keep an old allow by moving its record folder,
// and a full ledger that drops another account's removals cannot revive
// that account's allows. A key that cannot be removed gets a second key
// next to it, which the hook refuses as well; when that fails too the
// account is held closed in the gateway and the removal is still
// published, and the failure logged: the gateway's denial is the stricter
// answer.
//
// The record folder is located from the standalone layout, or else from
// the folder this guardian located last, or else from the data directory
// the guardian runs with (managed.StandaloneHookSessionDirForDataDir), so a
// failed lookup of the layout (on Windows, of the protected ProgramData
// registration) still removes the key the hook reads.
//
// The account is held closed (enterprisepolicy.MarkForeignHookRemovalPending:
// the gateway denies every guarded call of the account) when the ledger
// does not take the removals (the process clock is unavailable, or the
// storage refuses the write), and when the key could not be removed first.
// The mark is metadata of the account's private session store in the
// gateway's data directory: it needs no free space, and no standard user
// can reach it. Each later pass for the account, removals or not, records
// it once the key is removed: the files are not known any more, so it
// denies every agent process of the account that started before that
// pass, for every connector. The mark is cleared only after that ledger
// write. A mark that cannot be read is treated as set and never cleared.
// Failures are logged; the per-call check still applies.
func recordEnterpriseForeignHookRemovals(stderr io.Writer, account, home, connectorName string, paths []string) {
	identity, ok := connector.CanonicalUserScopedIdentity(account)
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if !ok || cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	if connectorName == "" {
		paths = nil
	}
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	pending, pendingErr := enterpriseForeignHookRemovalPending(identity)
	if pendingErr != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: read the pending removal mark of %s: %v\n",
			foreignGuardLogField(account, 256), pendingErr)
	}
	if len(paths) == 0 && !pending && pendingErr == nil {
		return
	}
	connectors := enterprisepolicy.StandaloneConnectors(cfg)
	every := make([]string, 0, len(connectors)+1)
	for _, name := range append(append([]string{}, connectors...), connectorName) {
		if name != "" && !slices.Contains(every, name) {
			every = append(every, name)
		}
	}
	var err, warn error
	closed := pending || pendingErr != nil
	hold := func(why string) {
		if closed {
			return
		}
		if markErr := enterpriseForeignHookMarkRemovalPending(identity); markErr != nil {
			err = errors.Join(err, fmt.Errorf("hold the account's guarded calls closed: %w", markErr))
			return
		}
		closed = true
		err = errors.Join(err, errors.New("the account's guarded calls are denied until a later pass "+why))
	}
	// The key goes first: from here on no allow written before proves
	// anything during an outage, whatever this pass publishes.
	root, rootErr := enterpriseForeignHookSessionRoot()
	trust := enterpriseForeignHookSessionKeyTrust()
	killErr := rootErr
	if killErr == nil {
		killErr = enterpriseForeignHookRetireSessionKey(root, trust)
	}
	if killErr != nil {
		err = errors.Join(err, fmt.Errorf("remove the protected session record key before the removal is published: %w", killErr))
		hold("can remove the protected session record key first")
	}
	// A held account, or one an earlier pass left held, is recorded only in
	// a pass that removed the key first.
	var unrecorded []string
	if pending && killErr == nil {
		unrecorded = every
	}
	ledgerErr := func() error {
		mark := agentprocess.Now()
		if mark == "" {
			return errors.New("the process clock is unavailable")
		}
		now := time.Now().UTC()
		var added []enterprisepolicy.ForeignHookRemoval
		for _, path := range paths {
			for _, name := range enterprisepolicy.ForeignHookRemovalConnectors(home, path, connectorName, connectors) {
				added = append(added, enterprisepolicy.ForeignHookRemoval{
					Identity: identity, Connector: name, Path: foreignGuardLogField(path, 512),
					At: now.Format(time.RFC3339), Mark: mark,
				})
			}
		}
		for _, name := range unrecorded {
			added = append(added, enterprisepolicy.ForeignHookRemoval{
				Identity: identity, Connector: name, Path: enterpriseForeignHookUnrecordedRemoval,
				At: now.Format(time.RFC3339), Mark: mark,
			})
		}
		if len(added) == 0 {
			return nil
		}
		return writeEnterpriseForeignHookRemovalLedger(stderr, added, now)
	}()
	if ledgerErr != nil {
		err = errors.Join(err, ledgerErr)
		hold("records the removal")
	}
	// The new key only after every write above, so that an allow decided
	// from the earlier ledger, or before the mark, carries a key that is
	// gone.
	if killErr == nil {
		if createErr := enterpriseForeignHookCreateSessionKey(root, trust); createErr != nil {
			warn = fmt.Errorf("make a new protected session record key (guarded calls block during a gateway outage until a later pass makes one): %w", createErr)
		}
	}
	if err == nil && pending && pendingErr == nil {
		if clearErr := enterpriseForeignHookClearRemovalPending(identity); clearErr != nil {
			err = fmt.Errorf("clear the pending removal mark, which the ledger now covers: %w", clearErr)
		}
	}
	if err = errors.Join(err, warn); err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: record the %s hook removal for %s: %v\n",
			connectorName, foreignGuardLogField(account, 256), err)
	}
}

// ensureEnterpriseForeignHookSessionKey gives the protected session records
// a key at every guardian pass when they have none
// (enterprisepolicy.EnsurePublishedSessionKey): the gateway removes it
// before every block, and a lifecycle run or a guardian pass that did not
// finish leaves none. A new key never makes an earlier record count. Only
// root or SYSTEM can make a key the hook accepts, so any other account does
// nothing. Under the removal lock, so it never makes a key between the
// removal and the ledger write of a pass in this process.
func ensureEnterpriseForeignHookSessionKey(stderr io.Writer) {
	if cfg == nil || !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() || !enterpriseForeignHookCanCreateSessionKey() {
		return
	}
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	root, err := enterpriseForeignHookSessionRoot()
	if err == nil {
		err = enterpriseForeignHookEnsureSessionKey(root, enterpriseForeignHookSessionKeyTrust())
	}
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: make the protected session record key (guarded calls block during a gateway outage until it exists): %v\n", err)
	}
}

// enterpriseForeignHookUnrecordedRemoval is the file a removal names when a
// pass records an account's pending mark: the files of the removal that
// set it are not known any more.
const enterpriseForeignHookUnrecordedRemoval = "a hook file DefenseClaw could not record at the time"

// writeEnterpriseForeignHookRemovalLedger adds added to the removal ledger
// in the guardian's authorization directory. A ledger too full to keep the
// denial of every account and connector
// (enterprisepolicy.EncodeForeignHookRemovals) names the accounts it drops:
// each is held closed before the ledger is written, or nothing is written.
// The caller removed the record key before, which ended their allows.
func writeEnterpriseForeignHookRemovalLedger(stderr io.Writer, added []enterprisepolicy.ForeignHookRemoval, now time.Time) error {
	dataDir := cfg.DataDir
	if !filepath.IsAbs(managed.HookGuardianAuthorizationDir(dataDir)) {
		return errors.New("the data directory is not an absolute path")
	}
	path := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), enterprisepolicy.ForeignHookRemovalsFile)
	existing, loadErr := loadEnterpriseForeignHookRemovals(path)
	if loadErr != nil {
		// The gateway cannot use this ledger either; replacing it keeps
		// the new removals.
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: replacing the removal ledger: %v\n", loadErr)
	}
	data, evicted, err := enterprisepolicy.EncodeForeignHookRemovals(existing, added, now)
	if err != nil {
		return err
	}
	for _, identity := range evicted {
		if err := enterpriseForeignHookMarkRemovalPending(identity); err != nil {
			return fmt.Errorf("hold %s closed, whose removals the full ledger cannot keep: %w", foreignGuardLogField(identity, 256), err)
		}
	}
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		return err
	}
	if err := writeEnterpriseHookProtectedFile(path, data); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return err
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return err
	}
	return enterpriseHookAuthorizationFileTrustCheck(path)
}

// enterpriseForeignHookSessionRoot is the folder of the protected session
// records (managed.StandaloneLayout.HookSessionDir): from the standalone
// layout, or else the folder the layout named last in this process (the
// Windows guardian is a service, so a lookup that fails for a moment does
// not leave a removal it cannot close where the hook looks, 1.0.4 guard
// loop round 3), or else from the guardian's data directory
// (managed.StandaloneHookSessionDirForDataDir), which names the same folder
// on a standalone host. Only when none names it is it an error: the
// guardian then cannot remove the record key, so it holds the account
// closed in the gateway (replaceable in tests).
var enterpriseForeignHookSessionRoot = func() (string, error) {
	root, err := enterpriseForeignHookSessionLayoutRoot()
	enterpriseForeignHookSessionRootSeen.Lock()
	defer enterpriseForeignHookSessionRootSeen.Unlock()
	if err == nil {
		enterpriseForeignHookSessionRootSeen.root = root
		return root, nil
	}
	if seen := enterpriseForeignHookSessionRootSeen.root; seen != "" {
		return seen, nil
	}
	if cfg != nil {
		if fallback, ok := enterpriseForeignHookSessionRootForDataDir(cfg.DataDir); ok {
			return fallback, nil
		}
	}
	return "", err
}

// enterpriseForeignHookSessionRootSeen is the record folder the standalone
// layout named last in this process (enterpriseForeignHookSessionRoot).
var enterpriseForeignHookSessionRootSeen struct {
	sync.Mutex
	root string
}

// enterpriseForeignHookSessionLayoutRoot is the record folder of the
// standalone layout. A layout that cannot be resolved (on Windows, a failed
// ProgramData lookup) is an error (replaceable in tests).
var enterpriseForeignHookSessionLayoutRoot = func() (string, error) {
	layout, _, _, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return "", fmt.Errorf("locate the protected session record folder: %w", err)
	}
	if strings.TrimSpace(layout.HookSessionDir) == "" {
		return "", errors.New("the standalone layout names no protected session record folder")
	}
	return layout.HookSessionDir, nil
}

// enterpriseForeignHookSessionRootForDataDir is the record folder of the
// standalone layout whose data directory is dataDir (replaceable in tests).
var enterpriseForeignHookSessionRootForDataDir = func(dataDir string) (string, bool) {
	return managed.StandaloneHookSessionDirForDataDir(runtime.GOOS, dataDir)
}

// enterpriseForeignHookRetireSessionKey removes the key of the protected
// session records before a pass publishes anything,
// enterpriseForeignHookCreateSessionKey makes a new one after it published,
// enterpriseForeignHookEnsureSessionKey makes one at every pass when there
// is none, enterpriseForeignHookSessionKeyTrust names the gateway service a
// Windows key file lets remove it, and
// enterpriseForeignHookCanCreateSessionKey reports a guardian that runs as
// root or SYSTEM (replaceable in tests).
var (
	enterpriseForeignHookRetireSessionKey = enterprisepolicy.RetirePublishedSessionKey
	enterpriseForeignHookCreateSessionKey = enterprisepolicy.CreatePublishedSessionKey
	enterpriseForeignHookEnsureSessionKey = enterprisepolicy.EnsurePublishedSessionKey
	enterpriseForeignHookSessionKeyTrust  = func() enterprisepolicy.PublishedSessionTrust {
		return enterprisepolicy.PublishedSessionTrust{ServiceAccount: `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc}
	}
	enterpriseForeignHookCanCreateSessionKey = enterpriseForeignHookRunsAsAdministrator
)

// enterpriseForeignHookRemovalPending, enterpriseForeignHookMarkRemovalPending
// and enterpriseForeignHookClearRemovalPending read, set and clear an
// account's pending removal mark, on its private session store under the
// gateway's data directory (enterprisepolicy.MarkForeignHookRemovalPending).
func enterpriseForeignHookRemovalPending(identity string) (bool, error) {
	return enterprisepolicy.ForeignHookRemovalPending(cfg.DataDir, identity)
}

func enterpriseForeignHookMarkRemovalPending(identity string) error {
	return enterprisepolicy.MarkForeignHookRemovalPending(cfg.DataDir, identity)
}

func enterpriseForeignHookClearRemovalPending(identity string) error {
	return enterprisepolicy.ClearForeignHookRemovalPending(cfg.DataDir, identity)
}

func loadEnterpriseForeignHookRemovals(path string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return nil, err
	}
	data, err := readEnterpriseHookBoundedFile(path, info, enterprisepolicy.ForeignHookRemovalsMaxBytes, "foreign-hook removal ledger")
	if err != nil {
		return nil, err
	}
	return enterprisepolicy.ParseForeignHookRemovals(data)
}
