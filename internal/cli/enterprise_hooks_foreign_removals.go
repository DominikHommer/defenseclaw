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
// storage refuses the write), when the account's protected session records
// are in a tree the hook refuses or in one the guardian cannot locate
// (enterprisepolicy.PublishedSessionAccountProblem): another account could
// have moved the account's folder away before the revocation, to bring the
// old allow back once the access is put back (GAP-0352 review), and when
// the revocation itself fails. The mark is metadata of the account's
// private session store in the gateway's data directory: it needs no free
// space, and no standard user can reach it, whatever it can do to the
// record tree. Each later pass for the account, removals or not, records it
// once the ledger takes it and the located tree is trusted: the files are
// not known any more, so it denies every agent process of the account that
// started before that pass, for every connector; then it revokes the
// account's records again and clears the mark. A mark that cannot be read
// is treated as set and never cleared.
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
	affected := make([][]string, 0, len(paths))
	var invalidated []string
	for _, path := range paths {
		names := enterprisepolicy.ForeignHookRemovalConnectors(home, path, connectorName, connectors)
		affected = append(affected, names)
		invalidated = append(invalidated, names...)
	}
	// The record tree is located once for the pass: a lookup that fails is a
	// tree the guardian cannot check or revoke in (GAP-0352 review loop
	// round 4), never "no records".
	root, treeErr := enterpriseForeignHookSessionRoot()
	if treeErr == nil {
		treeErr = enterpriseForeignHookSessionTreeProblem(root, identity)
	}
	// A held account is recorded only once its records can be revoked in a
	// tree the hook trusts.
	var unrecorded []string
	if pending && treeErr == nil {
		unrecorded = every
	}
	if pending || pendingErr != nil {
		invalidated = append(invalidated, every...)
	}
	var evicted []string
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
		var err error
		evicted, err = writeEnterpriseForeignHookRemovalLedger(stderr, added, now)
		return err
	}()
	held := pending || pendingErr != nil
	recorded := err == nil && treeErr == nil
	if !recorded {
		// The account stays held: the gateway denies every guarded call
		// of it, and all its records go.
		invalidated = append(invalidated, every...)
		if treeErr != nil {
			err = errors.Join(err, fmt.Errorf("its protected session records are in a folder another account could change, or one DefenseClaw cannot locate: %w", treeErr))
		}
		if !held {
			if markErr := enterpriseForeignHookMarkRemovalPending(identity); markErr != nil {
				err = errors.Join(err, fmt.Errorf("hold the account's guarded calls closed: %w", markErr))
			} else {
				held = true
				err = fmt.Errorf("%w (the account's guarded calls are denied until a later pass records the removal)", err)
			}
		}
	}
	slices.Sort(invalidated)
	invalidated = slices.Compact(invalidated)
	revokeErr := treeErr
	if root != "" {
		revokeErr = enterpriseForeignHookRevokeSessionRecords(root, identity, invalidated)
	}
	if revokeErr != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: revoke the protected session records of %s: %v\n",
			foreignGuardLogField(account, 256), revokeErr)
		// An allow that could not be revoked stands for an outage: hold the
		// account, so a later pass revokes it before the mark is cleared.
		if !held {
			if markErr := enterpriseForeignHookMarkRemovalPending(identity); markErr != nil {
				err = errors.Join(err, fmt.Errorf("hold the account's guarded calls closed until its records are revoked: %w", markErr))
			} else {
				err = errors.Join(err, errors.New("the account's guarded calls are denied until a later pass revokes its records"))
			}
		}
	}
	if recorded && revokeErr == nil && pending && pendingErr == nil {
		if clearErr := enterpriseForeignHookClearRemovalPending(root, identity); clearErr != nil {
			err = errors.Join(err, fmt.Errorf("clear the pending removal mark, which the ledger now covers: %w", clearErr))
		}
	}
	// Accounts whose denial the full ledger could not keep were held before
	// the write (writeEnterpriseForeignHookRemovalLedger); their allows go
	// now, as a held account's do.
	for _, other := range evicted {
		if root == "" {
			break
		}
		if revokeEvictedErr := enterpriseForeignHookRevokeSessionRecords(root, other, every); revokeEvictedErr != nil {
			fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: revoke the protected session records of %s, held because the removal ledger is full: %v\n",
				foreignGuardLogField(other, 256), revokeEvictedErr)
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
// in the guardian's authorization directory. A ledger too full to keep the
// denial of every account and connector
// (enterprisepolicy.EncodeForeignHookRemovals) names the accounts it drops:
// each is held closed before the ledger is written, or nothing is written,
// and the caller revokes their records after the write. It returns them.
func writeEnterpriseForeignHookRemovalLedger(stderr io.Writer, added []enterprisepolicy.ForeignHookRemoval, now time.Time) ([]string, error) {
	dataDir := cfg.DataDir
	if !filepath.IsAbs(managed.HookGuardianAuthorizationDir(dataDir)) {
		return nil, errors.New("the data directory is not an absolute path")
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
		return nil, err
	}
	for _, identity := range evicted {
		if err := enterpriseForeignHookMarkRemovalPending(identity); err != nil {
			return nil, fmt.Errorf("hold %s closed, whose removals the full ledger cannot keep: %w", foreignGuardLogField(identity, 256), err)
		}
	}
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		return evicted, err
	}
	if err := writeEnterpriseHookProtectedFile(path, data); err != nil {
		return evicted, err
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return evicted, err
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return evicted, err
	}
	return evicted, enterpriseHookAuthorizationFileTrustCheck(path)
}

// enterpriseForeignHookSessionRoot is the folder of the protected session
// records (managed.StandaloneLayout.HookSessionDir). A layout that cannot be
// resolved (on Windows, a failed ProgramData lookup) is an error: the
// guardian then can neither check nor revoke the account's records, so it
// holds the account (replaceable in tests).
var enterpriseForeignHookSessionRoot = func() (string, error) {
	layout, _, _, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return "", fmt.Errorf("locate the protected session record folder: %w", err)
	}
	if strings.TrimSpace(layout.HookSessionDir) == "" {
		return "", errors.New("the standalone layout names no protected session record folder")
	}
	return layout.HookSessionDir, nil
}

// enterpriseForeignHookSessionTreeProblem reports what the hook would refuse
// in the part of the protected session record tree under root that
// identity's records depend on (enterprisepolicy.PublishedSessionAccountProblem),
// with the accounts the hook trusts as owners. Replaceable in tests.
var enterpriseForeignHookSessionTreeProblem = func(root, identity string) error {
	layout, _, _, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return fmt.Errorf("the accounts that may own the protected session records are unknown: %w", err)
	}
	trust, err := enterpriseForeignHookSessionTrust(layout)
	if err != nil {
		return fmt.Errorf("the accounts that may own the protected session records are unknown: %w", err)
	}
	return enterprisepolicy.PublishedSessionAccountProblem(root, identity, trust)
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

func enterpriseForeignHookClearRemovalPending(root, identity string) error {
	return enterprisepolicy.ClearForeignHookRemovalPending(cfg.DataDir, root, identity)
}

// enterpriseForeignHookRevokeSessionRecords revokes identity's protected
// session records of connectors under root (replaceable in tests).
var enterpriseForeignHookRevokeSessionRecords = func(root, identity string, connectors []string) error {
	if len(connectors) == 0 {
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
