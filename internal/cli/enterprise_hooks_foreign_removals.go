// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
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
//
// When the ledger cannot be written, the removals go to the account's hold
// next to its protected session records (GAP-0352 review), which the
// gateway reads like the ledger: without it the gateway would answer the
// next exchange of a process that may still run the removed hook with an
// allow, and publish it again. The next ledger write takes the held
// removals in, and then the hold goes.
//
// Then it revokes the account's protected session records of those
// connectors (GAP-0352), after the ledger (or hold) write: the gateway
// withdraws an allow whose ledger or hold changed before it was published,
// so an exchange that read the earlier one either sees the change or
// published before this revocation, which removes its allow. Revoking only
// ever blocks, so it runs when neither could be written too.
func recordEnterpriseForeignHookRemovals(stderr io.Writer, account, home, connectorName string, paths []string) {
	identity, ok := connector.CanonicalUserScopedIdentity(account)
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if !ok || connectorName == "" || len(paths) == 0 || cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	connectors := enterprisepolicy.StandaloneConnectors(cfg)
	affected := make([][]string, 0, len(paths))
	var invalidated []string
	for _, path := range paths {
		names := enterprisepolicy.ForeignHookRemovalConnectors(home, path, connectorName, connectors)
		affected = append(affected, names)
		invalidated = append(invalidated, names...)
	}
	defer func() {
		if err := enterpriseForeignHookRevokeSessionRecords(identity, invalidated); err != nil {
			fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: revoke the protected session records of %s: %v\n",
				foreignGuardLogField(account, 256), err)
		}
	}()
	err := func() error {
		mark := agentprocess.Now()
		if mark == "" {
			return errors.New("the process clock is unavailable")
		}
		now := time.Now().UTC()
		added := make([]enterprisepolicy.ForeignHookRemoval, 0, len(invalidated))
		for i, path := range paths {
			for _, name := range affected[i] {
				added = append(added, enterprisepolicy.ForeignHookRemoval{
					Identity: identity, Connector: name, Path: foreignGuardLogField(path, 512),
					At: now.Format(time.RFC3339), Mark: mark,
				})
			}
		}
		held, holdErr := enterpriseForeignHookHeldRemovals(identity)
		if holdErr != nil {
			fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: read the held removals of %s: %v\n",
				foreignGuardLogField(account, 256), holdErr)
		}
		added = append(added, held...)
		if err := writeEnterpriseForeignHookRemovalLedger(stderr, added, now); err != nil {
			if holdErr := enterpriseForeignHookHoldRemovals(identity, added, now); holdErr != nil {
				return errors.Join(err, fmt.Errorf("hold the removals for the gateway: %w", holdErr))
			}
			return fmt.Errorf("%w (the gateway reads them from the account's hold until a ledger write succeeds)", err)
		}
		if len(held) > 0 && holdErr == nil {
			if err := enterpriseForeignHookReleaseHold(identity); err != nil {
				fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: remove the held removals of %s, which the ledger now holds: %v\n",
					foreignGuardLogField(account, 256), err)
			}
		}
		return nil
	}()
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: record the %s hook removal for %s: %v\n",
			connectorName, foreignGuardLogField(account, 256), err)
	}
}

// writeEnterpriseForeignHookRemovalLedger adds added to the removal ledger
// in the guardian's authorization directory.
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
	data, err := enterprisepolicy.EncodeForeignHookRemovals(existing, added, now)
	if err != nil {
		return err
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
// records (managed.StandaloneLayout.HookSessionDir), or false without the
// standalone layout (replaceable in tests).
var enterpriseForeignHookSessionRoot = func() (string, bool) {
	layout, _, _, err := standaloneEnterprisePolicyLayout()
	if err != nil || strings.TrimSpace(layout.HookSessionDir) == "" {
		return "", false
	}
	return layout.HookSessionDir, true
}

// enterpriseForeignHookHeldRemovals, enterpriseForeignHookHoldRemovals and
// enterpriseForeignHookReleaseHold read, write and delete the removals the
// guardian holds for an account because its ledger could not be written
// (enterprisepolicy.ForeignHookRemovalHoldPath); replaceable in tests. The
// hold is written like the ledger: replaced atomically, owned by root or
// Administrators, readable by the gateway service only.
var (
	enterpriseForeignHookHeldRemovals = func(identity string) ([]enterprisepolicy.ForeignHookRemoval, error) {
		root, ok := enterpriseForeignHookSessionRoot()
		if !ok {
			return nil, nil
		}
		removals, _, err := enterprisepolicy.ReadForeignHookRemovalHold(root, identity)
		return removals, err
	}
	enterpriseForeignHookHoldRemovals = func(identity string, removals []enterprisepolicy.ForeignHookRemoval, now time.Time) error {
		root, ok := enterpriseForeignHookSessionRoot()
		if !ok {
			return errors.New("this host has no protected session record folder")
		}
		path, ok := enterprisepolicy.ForeignHookRemovalHoldPath(root, identity)
		if !ok {
			return errors.New("the account has no protected session record folder")
		}
		data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, removals, now)
		if err != nil {
			return err
		}
		if err := writeEnterpriseHookProtectedFile(path, data); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o640); err != nil {
			return err
		}
		return enterpriseHookAuthorizationOwnershipSetter(path)
	}
	enterpriseForeignHookReleaseHold = func(identity string) error {
		root, ok := enterpriseForeignHookSessionRoot()
		if !ok {
			return nil
		}
		path, ok := enterprisepolicy.ForeignHookRemovalHoldPath(root, identity)
		if !ok {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
)

// enterpriseForeignHookRevokeSessionRecords revokes identity's protected
// session records of connectors (replaceable in tests). Without the
// standalone layout the hook finds no records either, so there is nothing
// to revoke.
var enterpriseForeignHookRevokeSessionRecords = func(identity string, connectors []string) error {
	root, ok := enterpriseForeignHookSessionRoot()
	if !ok {
		return nil
	}
	return enterprisepolicy.RemovePublishedForeignHookSessions(root, identity, connectors)
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
