// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/hex"
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
// per-user workers report their removals concurrently. It also guards
// enterpriseForeignHookCleanupTxs.
var enterpriseForeignHookRemovalsMu sync.Mutex

// enterpriseForeignHookCleanupTx is one cleanup transaction this process
// opened (beginEnterpriseForeignHookCleanup): its pending denials, whether
// its cleanup still runs, and, once it ended, whether it cannot tell exactly
// which files it changed.
type enterpriseForeignHookCleanupTx struct {
	entries   []enterprisepolicy.ForeignHookRemoval
	running   bool
	uncertain bool
}

// enterpriseForeignHookCleanupTxs are this process's cleanup transactions
// whose pending denials are, or may be, in the ledger, by token.
var enterpriseForeignHookCleanupTxs = map[string]*enterpriseForeignHookCleanupTx{}

// enterpriseForeignHookAbandonedAfter is how long the pending denial of a
// cleanup whose guardian process ended (a crash) stays before a ledger
// update settles it. Until then a worker of that cleanup may still edit
// files: a cleanup's denial is published just before its worker starts, and
// a foreign-cleanup worker exits within enterpriseHookWorkerTimeout plus
// five seconds, even on macOS, which has no parent-death signal.
var enterpriseForeignHookAbandonedAfter = 10 * time.Minute

// enterpriseForeignHookPendingMaxAge is the longest any pending denial no
// running cleanup of this process holds stays, whoever published it. A
// cleanup holds its denial from just before its worker starts until the
// worker ends, and both are bounded (resolveEnterpriseHookWorkerLaunch,
// enterpriseHookWorkerTimeout), so a denial this old belongs to a cleanup
// that ended even when its owner cannot be shown to have ended: a denial
// without an owner (an earlier 1.0.4 build published those), an owner whose
// process cannot be looked up, or an owner whose settle failed.
var enterpriseForeignHookPendingMaxAge = time.Hour

// enterpriseForeignHookCleanupOwner names this process in its pending
// denials, and enterpriseForeignHookOwnerEnded tells whether the process a
// pending denial names has ended. Replaceable in tests.
var (
	enterpriseForeignHookCleanupOwner = agentprocess.Self
	enterpriseForeignHookOwnerEnded   = agentprocess.Ended
)

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
	return err
}

// enterpriseForeignHookDenialConnectors names the connectors whose agents
// may load a file a cleanup will edit, given the files each connector's
// cleanup planned: the connectors its pending denial covers, the ones
// recordEnterpriseForeignHookRemovals records its removals for.
func enterpriseForeignHookDenialConnectors(home string, planned map[string][]string) []string {
	candidates := enterprisepolicy.StandaloneConnectors(cfg)
	names := []string{}
	for connectorName, paths := range planned {
		connectorName = strings.ToLower(strings.TrimSpace(connectorName))
		for _, path := range paths {
			for _, name := range enterprisepolicy.ForeignHookRemovalConnectors(home, path, connectorName, candidates) {
				if !slices.Contains(names, name) {
					names = append(names, name)
				}
			}
		}
	}
	slices.Sort(names)
	return names
}

// beginEnterpriseForeignHookCleanup opens a cleanup transaction for account
// before any of its user hook files can be removed: one ledger write
// publishes a pending denial for each of connectors, those whose agents may
// load a file the cleanup will edit (enterpriseForeignHookDenialConnectors).
// A cleanup with nothing to edit opens none. On an error nothing may be
// edited. finishEnterpriseForeignHookCleanup ends the transaction. The
// denial names this process, and none is published when it cannot be
// named in a way agentprocess.Ended can decide: a later pass could not tell
// that a guardian that died mid-cleanup had ended.
func beginEnterpriseForeignHookCleanup(stderr io.Writer, account string, connectors []string) (string, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return "", nil
	}
	identity, ok := connector.CanonicalUserScopedIdentity(account)
	if !ok {
		return "", errors.New("cannot bind the cleanup denial to an account")
	}
	names := []string{}
	for _, name := range connectors {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", errors.New("the cleanup denial names no connector")
	}
	owner := enterpriseForeignHookCleanupOwner()
	if !agentprocess.Decidable(owner) {
		return "", fmt.Errorf("the guardian cannot name its own process (%q), so the cleanup denial could not be settled if the guardian ended", foreignGuardLogField(owner, 128))
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	token := enterprisepolicy.ForeignHookCleanupPendingPath(hex.EncodeToString(id[:]), owner)
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	tx := &enterpriseForeignHookCleanupTx{running: true}
	enterpriseForeignHookCleanupTxs[token] = tx
	err := updateEnterpriseForeignHookLedger(stderr, func(now time.Time, mark string) []enterprisepolicy.ForeignHookRemoval {
		tx.entries = tx.entries[:0]
		for _, name := range names {
			tx.entries = append(tx.entries, enterprisepolicy.ForeignHookRemoval{
				Identity: identity, Connector: name, Path: token, At: now.Format(time.RFC3339Nano), Mark: mark,
			})
		}
		return tx.entries
	})
	if err != nil {
		// Nothing was edited: take back whatever was published, now or
		// on a later update. A denial the update never built (the ledger
		// could not be read) was never published.
		tx.running = false
		if tx.entries == nil {
			delete(enterpriseForeignHookCleanupTxs, token)
		} else {
			_ = updateEnterpriseForeignHookLedger(stderr, nil)
		}
		return "", err
	}
	return token, nil
}

// finishEnterpriseForeignHookCleanup ends cleanup transaction token once
// the caller recorded every removal it knows of. uncertain says it cannot
// tell that it knows all of them: its worker failed, an edit failed, or a
// removal could not be recorded. A certain cleanup's pending denial is
// cleared. An uncertain one's becomes, for each of its connectors, a
// removal at this instant (ForeignHookCleanupIncompletePath), after every
// edit the cleanup made: agents that started earlier stay denied until they
// restart, later ones loaded the files as they are now. If the ledger
// cannot be written the pending denial stays, and the next ledger update
// settles it.
func finishEnterpriseForeignHookCleanup(stderr io.Writer, token string, uncertain bool) error {
	if token == "" || cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	tx := enterpriseForeignHookCleanupTxs[token]
	if tx == nil {
		return nil
	}
	tx.running, tx.uncertain = false, uncertain
	return updateEnterpriseForeignHookLedger(stderr, nil)
}

// reconcileEnterpriseForeignHookCleanups settles the pending denials of
// cleanups that ended: this process's that a failed ledger write left, and
// those of a guardian process that ended without settling them
// (enterpriseForeignHookAbandonedAfter). Each cleanup pass runs it first,
// also one that cleans nothing, so an abandoned denial never outlives the
// next pass: it would deny every agent of its account, and of an account
// that later reuses the uid, forever.
func reconcileEnterpriseForeignHookCleanups(stderr io.Writer) {
	if cfg == nil || !cfg.StandaloneEnterprise() || !filepath.IsAbs(managed.HookGuardianAuthorizationDir(cfg.DataDir)) {
		return
	}
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	if err := updateEnterpriseForeignHookLedger(stderr, nil); err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: settle ended cleanups' pending denials: %v\n", err)
	}
}

// updateEnterpriseForeignHookLedger rewrites the removal ledger with the
// entries add returns (nil adds none), each of which must survive
// encoding, and settles the pending denials of ended cleanups
// (settleEnterpriseForeignHookPending). It writes only when something
// changed. A ledger that cannot be read is never replaced: the update
// fails. The caller holds enterpriseForeignHookRemovalsMu.
func updateEnterpriseForeignHookLedger(stderr io.Writer, add func(now time.Time, mark string) []enterprisepolicy.ForeignHookRemoval) error {
	dataDir := cfg.DataDir
	dir := managed.HookGuardianAuthorizationDir(dataDir)
	if !filepath.IsAbs(dir) {
		return errors.New("the data directory is not an absolute path")
	}
	mark := agentprocess.Now()
	if mark == "" {
		return errors.New("the process clock is unavailable")
	}
	now := time.Now().UTC()
	path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile)
	existing, err := loadEnterpriseForeignHookRemovals(path)
	if err != nil {
		// The gateway denies every call while the ledger cannot be read. A
		// new ledger would drop the removals it holds and allow the agents
		// they deny once it is read again, so it stays as it is until it can
		// be read again or an administrator removes it. Until then no
		// cleanup starts and ended cleanups keep their pending denials.
		return fmt.Errorf("the removal ledger cannot be read and is kept until it can be read again or an administrator removes %s: %w", path, err)
	}
	kept, added, settled := settleEnterpriseForeignHookPending(existing, now, mark)
	if add != nil {
		added = append(added, add(now, mark)...)
	}
	if len(added) == 0 && len(kept) == len(existing) {
		// Nothing changes; settled transactions have no denial left.
		for _, token := range settled {
			delete(enterpriseForeignHookCleanupTxs, token)
		}
		return nil
	}
	data, err := enterprisepolicy.EncodeForeignHookRemovals(kept, added, now)
	if err != nil {
		return err
	}
	retained, err := enterprisepolicy.ParseForeignHookRemovals(data)
	if err != nil {
		return err
	}
	for _, want := range added {
		if !slices.Contains(retained, want) {
			return errors.New("the removal ledger cannot retain the new denial")
		}
	}
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		return err
	}
	if err := writeEnterpriseHookGatewayRecord(path, data); err != nil {
		return err
	}
	for _, token := range settled {
		delete(enterpriseForeignHookCleanupTxs, token)
	}
	return nil
}

// settleEnterpriseForeignHookPending returns the ledger entries to keep,
// the removals that replace settled pending denials, and the settled
// transactions of this process. A pending denial stays while its cleanup
// may still edit files: this process's running cleanup, or another
// process's until that process ended over
// enterpriseForeignHookAbandonedAfter after it published the denial. A
// denial that cannot be tied to a process that ended stays until
// enterpriseForeignHookPendingMaxAge, never longer: its cleanup has ended by
// then. An ended cleanup that cannot tell what it changed (uncertain, or
// abandoned) leaves a removal at now for each connector its denial named.
func settleEnterpriseForeignHookPending(existing []enterprisepolicy.ForeignHookRemoval, now time.Time, mark string) (kept, added []enterprisepolicy.ForeignHookRemoval, settled []string) {
	incomplete := func(pending enterprisepolicy.ForeignHookRemoval) enterprisepolicy.ForeignHookRemoval {
		return enterprisepolicy.ForeignHookRemoval{
			Identity: pending.Identity, Connector: pending.Connector, Path: enterprisepolicy.ForeignHookCleanupIncompletePath,
			At: now.Format(time.RFC3339Nano), Mark: mark,
		}
	}
	for token, tx := range enterpriseForeignHookCleanupTxs {
		if tx.running {
			continue
		}
		settled = append(settled, token)
		if tx.uncertain {
			for _, entry := range tx.entries {
				added = append(added, incomplete(entry))
			}
		}
	}
	self := ""
	for _, entry := range existing {
		if !enterprisepolicy.ForeignHookCleanupPending(entry.Path) {
			kept = append(kept, entry)
			continue
		}
		if tx, ok := enterpriseForeignHookCleanupTxs[entry.Path]; ok {
			if tx.running {
				kept = append(kept, entry)
			}
			continue
		}
		if self == "" {
			self = enterpriseForeignHookCleanupOwner()
		}
		owner := enterprisepolicy.ForeignHookCleanupPendingOwner(entry.Path)
		at, err := time.Parse(time.RFC3339Nano, entry.At)
		age := now.Sub(at)
		// A date that does not parse, or lies past the bound either way (the
		// clock was set back), is no proof a cleanup still runs.
		expired := err != nil || age >= enterpriseForeignHookPendingMaxAge || age <= -enterpriseForeignHookPendingMaxAge
		abandoned := age >= enterpriseForeignHookAbandonedAfter && owner != "" && owner != self && enterpriseForeignHookOwnerEnded(owner)
		if !expired && !abandoned {
			kept = append(kept, entry)
			continue
		}
		added = append(added, incomplete(entry))
	}
	return kept, added, settled
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

// commitEnterpriseForeignHookRemovals publishes the ledger first and then
// waits for the exchanges that may have read the previous one. Online
// exchanges never wait on the commit: one that starts after the publication
// reads the removal, so a pending removal denies only the removed account's
// new calls, and nothing slow (staging, sync, ownership, trust checks)
// happens while the guardian holds the fence. The ledger does not depend on
// the lock files either: a removal it failed to record would let a process
// that loaded the removed hook be allowed once they are repaired, and the
// gateway refuses every exchange while the fence is unusable.
func commitEnterpriseForeignHookRemovals(stderr io.Writer, identity, home, connectorName string, paths []string) error {
	dataDir := cfg.DataDir
	guardianDir := managed.HookGuardianAuthorizationDir(dataDir)
	if !filepath.IsAbs(guardianDir) {
		return errors.New("the data directory is not an absolute path")
	}
	if _, err := hardenEnterpriseHookAuthorizationDir(dataDir); err != nil {
		return err
	}
	var problems []error
	if err := ensureEnterpriseForeignHookRemovalFence(guardianDir); err != nil {
		problems = append(problems, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), foreignHookRemovalLedgerLockWait)
	unlockLedger, err := enterprisepolicy.LockForeignHookRemovalsLedger(ctx, guardianDir)
	cancel()
	if err != nil {
		// Without the lock, a commit of another guardian process at the
		// same moment could drop one of the two; without the commit, this
		// removal is lost for sure.
		problems = append(problems, fmt.Errorf("committed without the ledger lock: %w", err))
	} else {
		defer unlockLedger()
	}
	mark := agentprocess.Now()
	if mark == "" {
		return errors.Join(append(problems, errors.New("the process clock is unavailable"))...)
	}
	now := time.Now().UTC()
	connectors := enterprisepolicy.StandaloneConnectors(cfg)
	added := make([]enterprisepolicy.ForeignHookRemoval, 0, len(paths))
	for _, path := range paths {
		for _, name := range enterprisepolicy.ForeignHookRemovalConnectors(home, path, connectorName, connectors) {
			added = append(added, enterprisepolicy.ForeignHookRemoval{
				Identity: identity, Connector: name, Path: foreignGuardLogField(path, 512),
				At: now.Format(time.RFC3339), Mark: mark,
			})
		}
	}
	path := filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)
	existing, loadErr := loadEnterpriseForeignHookRemovals(path)
	if loadErr != nil {
		// The gateway cannot use this ledger either; replacing it keeps
		// the new removals.
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: replacing the removal ledger: %v\n", loadErr)
	}
	data, err := enterprisepolicy.EncodeForeignHookRemovals(existing, added, now)
	if err != nil {
		return errors.Join(append(problems, err)...)
	}
	if err := publishEnterpriseHookProtectedFile(path, data); err != nil {
		return errors.Join(append(problems, err)...)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		problems = append(problems, err)
	}
	if _, err := enterprisepolicy.AwaitForeignHookRemovalExchanges(guardianDir); err != nil {
		problems = append(problems, err)
	}
	return errors.Join(problems...)
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
