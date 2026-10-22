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
// Then it bumps the generation of the protected session records
// (enterprisepolicy.BumpPublishedSessionGeneration, GAP-0352): every allow
// the gateway wrote before the bump, from the earlier ledger or not, proves
// nothing during an outage after it. The gateway reads the generation
// before the ledger, so an exchange that stamps its answer with the new
// generation read this ledger. No record has to be found or revoked, so no
// account can keep an old allow by moving its record folder, and a full
// ledger that drops another account's removals cannot revive that
// account's allows.
//
// Before it publishes anything (the ledger, or any account's pending mark)
// it closes the records where the hook looks (GAP-0352, 1.0.4 guard loop
// rounds 1 and 2): it holds them for the account
// (enterprisepolicy.HoldPublishedSessionRemoval: a hold the hook sees, in a
// folder no standard user can change), and then withdraws the generation
// (enterprisepolicy.WithdrawPublishedSessionGeneration: the generation file
// is removed, so no allow proves anything and every answer the gateway
// stamps until the bump carries none). Either one keeps the hook from
// honoring an allow while the gateway already denies from the new ledger,
// and both stay when the pass stops before its bump; the withdrawal also
// fails the last generation read of a hook check that found no hold just
// before the hold was made. The bump after the ledger creates the
// generation again past the one withdrawn, and the hold is released only
// after it succeeded. When neither can be put in place (no hold, and a
// generation file that can be neither removed nor bumped) the removal is
// still published, and the failure logged: the gateway's denial is the
// stricter answer, and withholding it would only make the gateway allow
// what the hook allows during an outage. A later
// pass for the account treats its own hold like a pending mark (the files
// may not have reached the ledger); a later pass for another account first
// holds the account the hold names closed in the gateway
// (MarkForeignHookRemovalPending), then bumps, then releases the hold, so a
// removed account that gets no more passes does not hold every account.
//
// When neither can be put in place, the account is held closed in the
// gateway and then its records are revoked
// (enterprisepolicy.RevokePublishedSessionAccount) before the ledger.
//
// The record folder is located from the standalone layout, or else from
// the folder this guardian located last, or else from the data directory
// the guardian runs with (managed.StandaloneHookSessionDirForDataDir), so a
// failed lookup of the layout (on Windows, of the protected ProgramData
// registration) still holds and bumps the folder the hook reads.
//
// The account is held closed (enterprisepolicy.MarkForeignHookRemovalPending:
// the gateway denies every guarded call of the account) when the ledger
// does not take the removals (the process clock is unavailable, or the
// storage refuses the write), and when the generation could not be bumped
// (the record folder cannot be located, or is missing and may come back
// with its own old generation). The mark is metadata of the account's
// private session store in the gateway's data directory: it needs no free
// space, and no standard user can reach it. Each later pass for the
// account, removals or not, records it once the record folder is located:
// the files are not known any more, so it denies every agent process of the
// account that started before that pass, for every connector. The mark is
// cleared only after that ledger write and a bump after it succeeded. A
// mark that cannot be read is treated as set and never cleared. Failures
// are logged; the per-call check still applies.
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
	// The record folder is located once for the pass. A lookup that fails
	// is a generation the guardian cannot bump (GAP-0352 review loop round
	// 4), never "no records".
	root, rootErr := enterpriseForeignHookSessionRoot()
	// The guardian's holds earlier passes left: this account's, and other
	// accounts'.
	ownHeld := false
	var others []enterprisepolicy.PublishedSessionRemovalHold
	var warn error
	if rootErr == nil {
		holds, holdsErr := enterprisepolicy.PublishedSessionRemovalHolds(root)
		warn = errors.Join(warn, holdsErr)
		for _, hold := range holds {
			switch hold.Identity {
			case identity:
				ownHeld = true
			case "":
				warn = errors.Join(warn, fmt.Errorf("%s names no account, so it stays until an administrator removes it", hold.Path))
			default:
				others = append(others, hold)
			}
		}
	}
	if len(paths) == 0 && !pending && pendingErr == nil && !ownHeld && len(others) == 0 {
		return
	}
	connectors := enterprisepolicy.StandaloneConnectors(cfg)
	every := make([]string, 0, len(connectors)+1)
	for _, name := range append(append([]string{}, connectors...), connectorName) {
		if name != "" && !slices.Contains(every, name) {
			every = append(every, name)
		}
	}
	var err error
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
	// The records are closed where the hook looks before anything is
	// published: from here until the bump below, the ledger or a mark may
	// deny what an allow of the current generation would still prove.
	var floor time.Time
	if rootErr == nil {
		holdErr := enterpriseForeignHookHoldSessionRecords(root, identity)
		if holdErr != nil {
			holdErr = fmt.Errorf("hold the protected session records during a gateway outage: %w", holdErr)
		}
		var withdrawErr error
		floor, withdrawErr = enterpriseForeignHookWithdrawSessionGeneration(root)
		if holdErr != nil && withdrawErr != nil {
			// Neither stays closed if this pass stops before its bump. The
			// account is held closed in the gateway first, so an exchange
			// that reads the generation the withdrawal may have bumped
			// instead is denied, and an allow the gateway publishes after
			// the revocation below is denied again by its recheck. Then
			// the account's own records are revoked where the hook reads
			// them (1.0.4 guard loop round 3). Only when that fails too is
			// the removal published with nothing the hook sees; the pass
			// says so.
			err = errors.Join(err, holdErr, withdrawErr)
			hold("can hold the protected session records or withdraw their generation")
			if revokeErr := enterpriseForeignHookRevokeSessionRecords(root, identity); revokeErr != nil {
				err = errors.Join(err, fmt.Errorf("revoke the account's protected session records: %w; the removal is published anyway, "+
					"and an allow written before this pass may pass during a gateway outage until a later pass closes the records", revokeErr))
			}
		} else if holdErr != nil {
			warn = errors.Join(warn, holdErr)
		}
	}
	// A held account, or one an earlier pass left held, is recorded only in
	// a pass that can bump after it.
	var unrecorded []string
	if (pending || ownHeld) && rootErr == nil {
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
	// Every other account a hold names is held closed in the gateway before
	// the bump that ends its hold.
	var drained []string
	for _, other := range others {
		if markErr := enterpriseForeignHookMarkRemovalPending(other.Identity); markErr != nil {
			warn = errors.Join(warn, fmt.Errorf("hold %s closed, whose earlier pass did not finish: %w", foreignGuardLogField(other.Identity, 256), markErr))
			continue
		}
		drained = append(drained, other.Identity)
	}
	// After every write above, so that an allow decided from the earlier
	// ledger, or before the mark, carries the generation this bump ends.
	bumpErr := rootErr
	if bumpErr == nil {
		bumpErr = enterpriseForeignHookBumpSessionGeneration(root, floor)
	}
	if bumpErr != nil {
		err = errors.Join(err, fmt.Errorf("invalidate the protected session records: %w", bumpErr))
		hold("invalidates the protected session records")
	} else {
		for _, other := range drained {
			warn = errors.Join(warn, enterprisepolicy.ReleasePublishedSessionRemoval(root, other))
		}
		// The gateway denies the removal from the ledger, or the whole
		// account from its mark.
		if ledgerErr == nil || closed {
			warn = errors.Join(warn, enterprisepolicy.ReleasePublishedSessionRemoval(root, identity))
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

// enterpriseForeignHookUnrecordedRemoval is the file a removal names when a
// pass records an account's pending mark: the files of the removal that
// set it are not known any more.
const enterpriseForeignHookUnrecordedRemoval = "a hook file DefenseClaw could not record at the time"

// writeEnterpriseForeignHookRemovalLedger adds added to the removal ledger
// in the guardian's authorization directory. A ledger too full to keep the
// denial of every account and connector
// (enterprisepolicy.EncodeForeignHookRemovals) names the accounts it drops:
// each is held closed before the ledger is written, or nothing is written.
// The caller's bump after the write ends their allows.
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
// guardian then cannot hold the records or bump their generation, so it
// holds the account closed in the gateway (replaceable in tests).
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

// enterpriseForeignHookHoldSessionRecords holds the protected session
// records under root for an account and
// enterpriseForeignHookWithdrawSessionGeneration withdraws their generation,
// both before a pass publishes anything,
// enterpriseForeignHookRevokeSessionRecords revokes the account's records
// when neither took, and enterpriseForeignHookBumpSessionGeneration starts
// the next generation past floor after it published (replaceable in
// tests).
var (
	enterpriseForeignHookHoldSessionRecords        = enterprisepolicy.HoldPublishedSessionRemoval
	enterpriseForeignHookWithdrawSessionGeneration = enterprisepolicy.WithdrawPublishedSessionGeneration
	enterpriseForeignHookRevokeSessionRecords      = enterprisepolicy.RevokePublishedSessionAccount
	enterpriseForeignHookBumpSessionGeneration     = enterprisepolicy.BumpPublishedSessionGenerationPast
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
