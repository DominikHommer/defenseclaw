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
// that could have loaded one started before the recorded time. A failed
// ledger write leaves the pending cleanup denial in place.
func recordEnterpriseForeignHookRemovals(stderr io.Writer, account, home, connectorName string, paths []string) error {
	identity, ok := connector.CanonicalUserScopedIdentity(account)
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if len(paths) == 0 || cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	if !ok || connectorName == "" {
		return errors.New("cannot bind the hook removal to an account and connector")
	}
	connectors := enterprisepolicy.StandaloneConnectors(cfg)
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	err := updateEnterpriseForeignHookLedger(stderr, func(now time.Time, mark string) []enterprisepolicy.ForeignHookRemoval {
		added := make([]enterprisepolicy.ForeignHookRemoval, 0, len(paths))
		for _, path := range paths {
			for _, name := range enterprisepolicy.ForeignHookRemovalConnectors(home, path, connectorName, connectors) {
				added = append(added, enterprisepolicy.ForeignHookRemoval{
					Identity: identity, Connector: name, Path: foreignGuardLogField(path, 512),
					At: now.Format(time.RFC3339), Mark: mark,
				})
			}
		}
		return added
	})
	if err != nil {
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
// edited. finishEnterpriseForeignHookCleanup ends the transaction.
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
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	token := enterprisepolicy.ForeignHookCleanupPendingPath(hex.EncodeToString(id[:]), enterpriseForeignHookCleanupOwner())
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
	if err := writeEnterpriseHookProtectedFile(path, data); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return err
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return err
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
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
// denial that cannot be tied to a process that ended stays. An ended cleanup
// that cannot tell what it changed (uncertain, or abandoned) leaves a
// removal at now for each connector its denial named.
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
		if owner == "" || owner == self || err != nil || now.Sub(at) < enterpriseForeignHookAbandonedAfter || !enterpriseForeignHookOwnerEnded(owner) {
			kept = append(kept, entry)
			continue
		}
		added = append(added, incomplete(entry))
	}
	return kept, added, settled
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
