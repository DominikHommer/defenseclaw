// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
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
// The account is held closed (enterprisepolicy.MarkForeignHookRemovalPending:
// the gateway denies every guarded call of the account) when the ledger
// does not take the removals (the process clock is unavailable, or the
// storage refuses the write), and when the account's protected session
// records are in a tree the hook refuses
// (enterprisepolicy.PublishedSessionAccountProblem): another account could
// have moved the account's folder away before the revocation, to bring the
// old allow back once the access is put back (GAP-0352 review). The mark is
// metadata of the account's private session store in the gateway's data
// directory: it needs no free space, and no standard user can reach it,
// whatever it can do to the record tree. Each later pass for the account,
// removals or not, records it once the ledger takes it and the tree is
// trusted: the files are not known any more, so it denies every agent
// process of the account that started before that pass, for every
// connector; then it revokes the account's records again and clears the
// mark.
//
// Then it revokes the account's protected session records of those
// connectors (GAP-0352), after the ledger or mark write; all of them while
// the account is held. The gateway withdraws an allow whose ledger or mark
// changed before it was published, so an exchange that read the earlier
// state either sees the change or published before this revocation, which
// removes its allow. Revoking only ever blocks, so it runs when nothing
// could be written too.
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
	if len(paths) == 0 && !pending {
		return
	}
	connectors := enterprisepolicy.StandaloneConnectors(cfg)
	every := make([]string, 0, len(connectors)+1)
	for _, name := range append(append([]string{}, connectors...), connectorName) {
		if name != "" && !slices.Contains(every, name) {
			every = append(every, name)
		}
	}
	affected := make([][]string, 0, len(paths))
	var invalidated []string
	for _, path := range paths {
		names := enterprisepolicy.ForeignHookRemovalConnectors(home, path, connectorName, connectors)
		affected = append(affected, names)
		invalidated = append(invalidated, names...)
	}
	treeErr := enterpriseForeignHookSessionTreeProblem(identity)
	// A held account is recorded only once its records can be revoked in a
	// tree the hook trusts.
	var unrecorded []string
	if pending && treeErr == nil {
		unrecorded = every
	}
	if pending {
		invalidated = append(invalidated, every...)
	}
	defer func() {
		slices.Sort(invalidated)
		invalidated = slices.Compact(invalidated)
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
	switch {
	case err == nil && treeErr == nil:
		if pending {
			if clearErr := enterpriseForeignHookClearRemovalPending(identity); clearErr != nil {
				err = fmt.Errorf("clear the pending removal mark, which the ledger now covers: %w", clearErr)
			}
		}
	default:
		// The account stays held: the gateway denies every guarded call
		// of it, and all its records go.
		invalidated = append(invalidated, every...)
		if treeErr != nil {
			err = errors.Join(err, fmt.Errorf("its protected session records are in a folder another account could change: %w", treeErr))
		}
		if !pending {
			if markErr := enterpriseForeignHookMarkRemovalPending(identity); markErr != nil {
				err = errors.Join(err, fmt.Errorf("hold the account's guarded calls closed: %w", markErr))
			} else {
				err = fmt.Errorf("%w (the account's guarded calls are denied until a later pass records the removal)", err)
			}
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: record the %s hook removal for %s: %v\n",
			connectorName, foreignGuardLogField(account, 256), err)
	}
}

// enterpriseForeignHookUnrecordedRemoval is the file a removal names when a
// pass records an account's pending mark: the files of the removal that
// set it are not known any more.
const enterpriseForeignHookUnrecordedRemoval = "a hook file DefenseClaw could not record at the time"

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

// enterpriseForeignHookSessionTreeProblem reports what the hook would refuse
// in the part of the protected session record tree that identity's records
// depend on (enterprisepolicy.PublishedSessionAccountProblem), with the
// accounts the hook trusts as owners; nil without the standalone layout.
// Replaceable in tests.
var enterpriseForeignHookSessionTreeProblem = func(identity string) error {
	layout, _, _, err := standaloneEnterprisePolicyLayout()
	if err != nil || strings.TrimSpace(layout.HookSessionDir) == "" {
		return nil
	}
	if _, err := os.Lstat(layout.HookSessionDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	trust, err := enterpriseForeignHookSessionTrust(layout)
	if err != nil {
		return fmt.Errorf("the accounts that may own the protected session records are unknown: %w", err)
	}
	return enterprisepolicy.PublishedSessionAccountProblem(layout.HookSessionDir, identity, trust)
}

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
	root, _ := enterpriseForeignHookSessionRoot()
	return enterprisepolicy.ClearForeignHookRemovalPending(cfg.DataDir, root, identity)
}

// enterpriseForeignHookRevokeSessionRecords revokes identity's protected
// session records of connectors (replaceable in tests). Without the
// standalone layout the hook finds no records either, so there is nothing
// to revoke.
var enterpriseForeignHookRevokeSessionRecords = func(identity string, connectors []string) error {
	root, ok := enterpriseForeignHookSessionRoot()
	if !ok || len(connectors) == 0 {
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
