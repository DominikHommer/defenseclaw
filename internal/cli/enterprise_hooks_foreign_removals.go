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
func recordEnterpriseForeignHookRemovals(stderr io.Writer, account, home, connectorName string, paths []string) error {
	identity, ok := connector.CanonicalUserScopedIdentity(account)
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if !ok || connectorName == "" || len(paths) == 0 || cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	err := func() error {
		dataDir := cfg.DataDir
		if !filepath.IsAbs(managed.HookGuardianAuthorizationDir(dataDir)) {
			return errors.New("the data directory is not an absolute path")
		}
		mark := agentprocess.Now()
		if mark == "" {
			return errors.New("the process clock is unavailable")
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
		kept, err := enterprisepolicy.ParseForeignHookRemovals(data)
		if err != nil {
			return err
		}
		for _, want := range added {
			found := false
			for _, got := range kept {
				if got == want {
					found = true
					break
				}
			}
			if !found {
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
		return enterpriseHookAuthorizationFileTrustCheck(path)
	}()
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: record the %s hook removal for %s: %v\n",
			connectorName, foreignGuardLogField(account, 256), err)
	}
	return err
}

// beginEnterpriseForeignHookCleanup publishes a denial before any user hook
// file can be removed. All governed connectors are covered because several
// can load the same file. A failed publication refuses cleanup.
func beginEnterpriseForeignHookCleanup(stderr io.Writer, account, home string) (string, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return "", nil
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	token := enterprisepolicy.ForeignHookCleanupPendingPrefix + hex.EncodeToString(id[:]) + ">"
	for _, name := range enterprisepolicy.StandaloneConnectors(cfg) {
		if err := recordEnterpriseForeignHookRemovals(stderr, account, home, name, []string{token}); err != nil {
			return "", err
		}
	}
	return token, nil
}

// finishEnterpriseForeignHookCleanup removes only this cleanup's pending
// denial, after all of its actual removals were committed. On failure the
// pending denial stays, so an uncertain write cannot permit an old hook.
func finishEnterpriseForeignHookCleanup(account, token string) error {
	if token == "" || cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	identity, ok := connector.CanonicalUserScopedIdentity(account)
	if !ok {
		return errors.New("cannot bind the cleanup to an account")
	}
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	dataDir := cfg.DataDir
	path := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), enterprisepolicy.ForeignHookRemovalsFile)
	existing, err := loadEnterpriseForeignHookRemovals(path)
	if err != nil {
		return err
	}
	kept := existing[:0:0]
	for _, removal := range existing {
		if removal.Identity != identity || removal.Path != token {
			kept = append(kept, removal)
		}
	}
	data, err := enterprisepolicy.EncodeForeignHookRemovals(kept, nil, time.Now().UTC())
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
