// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// foreignHookRemovalLedgerLockWait bounds the wait for another guardian
// process's ledger commit; tests shorten it.
var foreignHookRemovalLedgerLockWait = 5 * time.Second

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
// that could have loaded one started before the recorded time. Failures are
// logged; the per-call check still applies.
func recordEnterpriseForeignHookRemovals(stderr io.Writer, account, home, connectorName string, paths []string) {
	identity, ok := connector.CanonicalUserScopedIdentity(account)
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if !ok || connectorName == "" || len(paths) == 0 || cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	if err := commitEnterpriseForeignHookRemovals(stderr, identity, home, connectorName, paths); err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: record the %s hook removal for %s: %v\n",
			connectorName, foreignGuardLogField(account, 256), err)
	}
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
