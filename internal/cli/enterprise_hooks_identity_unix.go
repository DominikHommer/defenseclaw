//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Identity spool (standalone profile, Linux and macOS). After a reconcile
// the guardian resolves the privileged directory facts of every enrolled
// account (enterprisehooks.WriteIdentitySpool) in the background, when the
// enrolled accounts changed or the refresh interval elapsed, so the gateway
// can report a verified UPN its sandbox cannot read itself.

// Successful passes refresh before the gateway's identity cache expires.
// Failed passes retry on the guardian's next one-minute reconcile tick.
const enterpriseHookIdentitySpoolInterval = 15 * time.Minute
const enterpriseHookIdentitySpoolRetryInterval = time.Minute

// enterpriseHookLoadIdentityAccounts is replaceable in tests (the record is
// root-only).
var enterpriseHookLoadIdentityAccounts = enterprisehooks.LoadUnixIdentityAccounts

var enterpriseHookIdentitySpoolState struct {
	sync.Mutex
	running     bool
	last        time.Time
	fingerprint string
	failed      bool
}

// The directory's return after an outage (enterprisehooks.DirectoryCachesStale):
// while the system's directory caches list an enrolled Active Directory
// account without its domain groups, the guardian asks every
// enterpriseHookDirectoryReturnPoll whether a domain controller of that
// domain answers, and flushes the caches when one does, so the accounts get
// their groups at the gateway's next lookup (#1197). A flush that did not
// clear them is repeated after enterpriseHookDirectoryFlushGap, doubling to
// enterpriseHookDirectoryFlushGapMax. A watch ends once the caches list the
// groups again, or after enterpriseHookDirectoryWatchLimit; the next
// reconcile tick starts another with the accounts enrolled then.
const (
	enterpriseHookDirectoryReturnPoll  = 15 * time.Second
	enterpriseHookDirectoryFlushGap    = 2 * time.Minute
	enterpriseHookDirectoryFlushGapMax = 15 * time.Minute
	enterpriseHookDirectoryWatchLimit  = 10 * time.Minute
)

// enterpriseHookDirectoryReturnDeps are the watch's lookups, flush and
// clock; tests replace them.
type enterpriseHookDirectoryReturnDeps struct {
	stale   func(dir string, accounts []enterprisehooks.IdentitySpoolAccount) (string, bool)
	answers func(ctx context.Context, domain string) bool
	flush   func(ctx context.Context) error
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) bool
}

var enterpriseHookDirectoryReturn = enterpriseHookDirectoryReturnDeps{
	stale:   enterprisehooks.DirectoryCachesStale,
	answers: enterprisehooks.DomainControllerAnswers,
	flush:   enterprisehooks.FlushDirectoryCaches,
	now:     time.Now,
	sleep: func(ctx context.Context, d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	},
}

var enterpriseHookDirectoryReturnState struct {
	sync.Mutex
	watching  bool
	lastFlush time.Time
	gap       time.Duration
}

// enterpriseHookIdentitySpoolAccounts lists the accounts a pass resolves
// identity facts for, and the keys that tell whether they changed.
func enterpriseHookIdentitySpoolAccounts(stderr io.Writer, run enterpriseHookReconcileRun) ([]enterprisehooks.IdentitySpoolAccount, []string) {
	accounts := []enterprisehooks.IdentitySpoolAccount{}
	keys := []string{}
	seen := map[int]bool{}
	// Manifest names may be NSS aliases. Only a name resolved by UID can
	// distinguish a reassigned UID from an alias of the same account in the
	// spool; an unavailable lookup leaves the name empty and preserves the
	// prior record while the gateway validates it independently.
	canonicalUser := func(uid int) string {
		account, err := enterprisehooks.StandaloneResolver().LookupUID(uid)
		if err == nil && account.UID == uid {
			return account.Name
		}
		return ""
	}
	for _, row := range run.Rows {
		// A pending row with a resolved uid (its home is not available, or
		// was recreated) stays enrolled: its record keeps being refreshed,
		// since a pass removes the records of the accounts it does not list
		// (GAP-1113).
		if row.UID <= 0 || seen[row.UID] {
			continue
		}
		seen[row.UID] = true
		// The manifest's spelling is not proof of the UID's current name.
		// macOS directory collection also needs this canonical name.
		user := canonicalUser(row.UID)
		accounts = append(accounts, enterprisehooks.IdentitySpoolAccount{UID: row.UID, User: user})
		keys = append(keys, strconv.Itoa(row.UID)+":"+user)
	}
	// Eligible accounts without rows, and accounts whose home is untrusted,
	// keep their identity record too: a standard user who makes his home
	// group-writable must not drop the profile assigned to his UPN to the
	// default (GAP-0714).
	if strings.TrimSpace(run.Manifest) != "" {
		extra, err := enterpriseHookLoadIdentityAccounts(enterprisehooks.UnixEligibleAccountsPath(run.Manifest))
		if err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: eligible accounts: %v\n", err)
		}
		if enterpriseHookManifestEnrollment() {
			extra = enterprisehooks.ManifestEnrolledAccounts(extra, enterprisehooks.Manifest{Targets: run.Targets})
		}
		for _, account := range extra {
			if account.UID <= 0 || seen[account.UID] {
				continue
			}
			seen[account.UID] = true
			user := canonicalUser(account.UID)
			accounts = append(accounts, enterprisehooks.IdentitySpoolAccount{UID: account.UID, User: user})
			keys = append(keys, strconv.Itoa(account.UID)+":"+user)
		}
	}
	return accounts, keys
}

func startEnterpriseHookIdentitySpool(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	dir := enterprisehooks.IdentitySpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
	if dir == "" {
		return
	}
	// The guardian follows a pushed config's trusted child domains, as the
	// gateway does on reload (GAP-1255).
	useridentity.SetTrustedADChildDomains(cfg.AIDiscovery.TrustedADChildDomains)
	accounts, keys := enterpriseHookIdentitySpoolAccounts(stderr, run)
	startEnterpriseHookDirectoryReturnWatch(ctx, stderr, dir, accounts)
	sort.Strings(keys)
	fingerprint := strings.Join(keys, ";")
	now := time.Now()
	state := &enterpriseHookIdentitySpoolState
	state.Lock()
	interval := enterpriseHookIdentitySpoolInterval
	if state.failed {
		interval = enterpriseHookIdentitySpoolRetryInterval
	}
	// The interval runs on the monotonic clock, but the gateway trusts a
	// record by its wall-clock age: after a clock step the records are
	// rewritten at the next one-minute tick (GAP-0921).
	_, _, stepped := enterprisehooks.IdentitySpoolStale(dir, now, enterpriseHookIdentitySpoolInterval+2*enterpriseHookIdentitySpoolRetryInterval)
	due := !state.running && (fingerprint != state.fingerprint || now.Sub(state.last) >= interval || stepped)
	if due {
		state.running = true
	}
	state.Unlock()
	if !due {
		return
	}
	go func() {
		var passErr error
		defer func() {
			state.Lock()
			state.running = false
			state.last = time.Now()
			state.fingerprint = fingerprint
			state.failed = passErr != nil
			state.Unlock()
		}()
		if err := ensureEnterpriseHookStandaloneAuthDir(managed.HookGuardianAuthorizationDir(cfg.DataDir)); err != nil {
			passErr = err
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v\n", err)
			return
		}
		logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
		passErr = enterprisehooks.WriteIdentitySpool(ctx, dir, accounts, enterpriseHookAuthorizationOwnershipSetter, logf)
		if passErr != nil {
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v\n", passErr)
		}
	}()
}

// startEnterpriseHookDirectoryReturnWatch starts the watch for the
// directory's return (enterpriseHookWatchDirectoryReturn) unless one runs.
func startEnterpriseHookDirectoryReturnWatch(ctx context.Context, stderr io.Writer, dir string,
	accounts []enterprisehooks.IdentitySpoolAccount) {
	state := &enterpriseHookDirectoryReturnState
	state.Lock()
	if state.watching || len(accounts) == 0 {
		state.Unlock()
		return
	}
	state.watching = true
	state.Unlock()
	go func() {
		defer func() {
			state.Lock()
			state.watching = false
			state.Unlock()
		}()
		enterpriseHookWatchDirectoryReturn(ctx, stderr, enterpriseHookDirectoryReturn, dir, accounts)
	}()
}

// enterpriseHookWatchDirectoryReturn flushes the directory caches once the
// domain controller answers again while they still list an Active Directory
// account without its domain groups, and never while it does not answer:
// those caches are then all the Mac has. It returns once the caches list the
// groups (or never lacked them), at the watch limit, or when ctx ends.
func enterpriseHookWatchDirectoryReturn(ctx context.Context, stderr io.Writer, deps enterpriseHookDirectoryReturnDeps, dir string,
	accounts []enterprisehooks.IdentitySpoolAccount) {
	state := &enterpriseHookDirectoryReturnState
	until := deps.now().Add(enterpriseHookDirectoryWatchLimit)
	for {
		domain, stale := deps.stale(dir, accounts)
		if !stale {
			state.Lock()
			state.gap = 0
			state.Unlock()
			return
		}
		state.Lock()
		due := state.lastFlush.IsZero() || deps.now().Sub(state.lastFlush) >= state.gap
		state.Unlock()
		if due && deps.answers(ctx, domain) {
			err := deps.flush(ctx)
			state.Lock()
			state.lastFlush = deps.now()
			state.gap = min(max(2*state.gap, enterpriseHookDirectoryFlushGap), enterpriseHookDirectoryFlushGapMax)
			state.Unlock()
			if err != nil {
				fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again, but the directory caches "+
					"were not flushed: %v\n", domain, err)
			} else {
				fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again while the directory caches "+
					"still list an account without its domain groups; flushed the caches, so accounts get their groups at "+
					"their next lookup\n", domain)
			}
		}
		if !deps.now().Before(until) || !deps.sleep(ctx, enterpriseHookDirectoryReturnPoll) {
			return
		}
	}
}
