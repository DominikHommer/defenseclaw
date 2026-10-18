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
	"slices"
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
// while the system's directory caches list enrolled Active Directory
// accounts without their domain groups, the guardian asks every
// enterpriseHookDirectoryReturnPoll whether a domain controller of each of
// those accounts' domains answers, and flushes the caches when one does, so
// the accounts get their groups at the gateway's next lookup (#1197). Each
// domain is asked and backed off on its own: a domain still away does not
// hold up one that is back, and one domain's flush does not delay another's.
// A flush that did not clear a domain's accounts is repeated for it after
// enterpriseHookDirectoryFlushGap, doubling to
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
	stale   func(dir string, accounts []enterprisehooks.IdentitySpoolAccount) []string
	answers func(ctx context.Context, domain string) bool
	flush   func(ctx context.Context) error
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) bool
	// domains lists the enrolled accounts' Active Directory domains, and
	// mark writes the ones whose domain controllers stopped answering
	// (enterpriseHookWatchDirectoryReach).
	domains func(dir string, accounts []enterprisehooks.IdentitySpoolAccount) []string
	mark    func(dir string, domains []string) error
	// awayUnseen counts a domain that does not answer as away even when it
	// never answered since the guardian started: SSSD reports its own
	// offline state (enterprisehooks.DirectoryAwayWithoutAnswer).
	awayUnseen bool
}

var enterpriseHookDirectoryReturn = enterpriseHookDirectoryReturnDeps{
	stale:   enterprisehooks.DirectoryCachesStale,
	answers: enterprisehooks.DirectoryAnswers,
	flush:   enterprisehooks.FlushDirectoryCaches,
	domains: enterprisehooks.DirectoryDomains,
	mark: func(dir string, domains []string) error {
		return enterprisehooks.WriteDirectoryUnreachable(dir, domains, time.Now(), enterpriseHookAuthorizationOwnershipSetter)
	},
	awayUnseen: enterprisehooks.DirectoryAwayWithoutAnswer,
	now:        time.Now,
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
	watching bool
	// flushed holds, for each domain whose return flushed the caches while
	// they still listed one of its accounts without its groups, when it did
	// and the gap before its next flush. A domain is dropped once none of
	// its accounts is listed so.
	flushed map[string]enterpriseHookDirectoryFlush
}

// enterpriseHookDirectoryReachState is the domain controller check's
// (enterpriseHookWatchDirectoryReach): the domains whose domain controllers
// answered at least once since the guardian started (seen), those that
// stopped answering after that (away), and whether the guardian last wrote
// a non-empty list (marked).
var enterpriseHookDirectoryReachState struct {
	sync.Mutex
	watching bool
	seen     map[string]bool
	away     map[string]bool
	marked   bool
}

// enterpriseHookDirectoryFlush is one domain's flush backoff.
type enterpriseHookDirectoryFlush struct {
	at  time.Time
	gap time.Duration
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
	startEnterpriseHookDirectoryReachWatch(ctx, stderr, dir, accounts)
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
// directory's return (enterpriseHookWatchDirectoryReturn) unless one runs,
// on a system whose caches keep serving outage answers (a Mac).
func startEnterpriseHookDirectoryReturnWatch(ctx context.Context, stderr io.Writer, dir string,
	accounts []enterprisehooks.IdentitySpoolAccount) {
	if !enterprisehooks.DirectoryCachesHoldOutageAnswers {
		return
	}
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
		domains := deps.stale(dir, accounts)
		now := deps.now()
		var due []string
		state.Lock()
		for domain := range state.flushed {
			if !slices.Contains(domains, domain) {
				delete(state.flushed, domain)
			}
		}
		for _, domain := range domains {
			if last, ok := state.flushed[domain]; !ok || now.Sub(last.at) >= last.gap {
				due = append(due, domain)
			}
		}
		state.Unlock()
		if len(domains) == 0 {
			return
		}
		if back := enterpriseHookDomainsAnswering(ctx, deps.answers, due); len(back) > 0 {
			err := deps.flush(ctx)
			at := deps.now()
			state.Lock()
			if state.flushed == nil {
				state.flushed = map[string]enterpriseHookDirectoryFlush{}
			}
			for _, domain := range back {
				gap := min(max(2*state.flushed[domain].gap, enterpriseHookDirectoryFlushGap), enterpriseHookDirectoryFlushGapMax)
				state.flushed[domain] = enterpriseHookDirectoryFlush{at: at, gap: gap}
			}
			state.Unlock()
			names := strings.Join(back, ", ")
			if err != nil {
				fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again, but the directory caches "+
					"were not flushed: %v\n", names, err)
			} else {
				fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again while the directory caches "+
					"still list an account without its domain groups; flushed the caches, so accounts get their groups at "+
					"their next lookup\n", names)
			}
		}
		if !deps.now().Before(until) || !deps.sleep(ctx, enterpriseHookDirectoryReturnPoll) {
			return
		}
	}
}

// enterpriseHookDomainsAnswering asks each domain at once whether one of its
// domain controllers answers (each probe is bounded on its own), so a domain
// that is away, whose probe runs to its deadline, does not delay the others,
// and returns the domains that answer, in their order.
func enterpriseHookDomainsAnswering(ctx context.Context, answers func(ctx context.Context, domain string) bool, domains []string) []string {
	ok := make([]bool, len(domains))
	var wg sync.WaitGroup
	for i, domain := range domains {
		wg.Go(func() { ok[i] = answers(ctx, domain) })
	}
	wg.Wait()
	var back []string
	for i, domain := range domains {
		if ok[i] {
			back = append(back, domain)
		}
	}
	return back
}

// startEnterpriseHookDirectoryReachWatch starts the domain controller check
// (enterpriseHookWatchDirectoryReach) unless one runs. The guardian's
// reconcile tick calls it about once a minute.
func startEnterpriseHookDirectoryReachWatch(ctx context.Context, stderr io.Writer, dir string,
	accounts []enterprisehooks.IdentitySpoolAccount) {
	state := &enterpriseHookDirectoryReachState
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
		enterpriseHookWatchDirectoryReach(ctx, stderr, enterpriseHookDirectoryReturn, dir, accounts)
	}()
}

// enterpriseHookWatchDirectoryReach checks whether a domain controller of
// each enrolled account's Active Directory domain answers (macOS), or whether
// SSSD is online for each enrolled account's SSSD domain (Linux,
// enterprisehooks.DirectoryAnswers). A domain that answered before and no
// longer does is away (on Linux also one SSSD reports offline from the
// start, deps.awayUnseen): the guardian writes the away domains to
// the identity spool (enterprisehooks.DirectoryUnreachableFile), so the
// gateway takes their accounts' lookups as failed instead of trusting the
// groups Open Directory lists then, and checks again every
// enterpriseHookDirectoryReturnPoll. Once a domain answers again, the
// directory caches are flushed: they hold the answers Open Directory or SSSD
// gave while it was away, without the accounts' other domain groups (GAP-0092,
// GAP-0095, GAP-0191). It returns once no domain is away, after one check when none
// was, or when ctx ends.
func enterpriseHookWatchDirectoryReach(ctx context.Context, stderr io.Writer, deps enterpriseHookDirectoryReturnDeps, dir string,
	accounts []enterprisehooks.IdentitySpoolAccount) {
	if deps.domains == nil {
		return
	}
	state := &enterpriseHookDirectoryReachState
	for {
		domains := deps.domains(dir, accounts)
		answering := enterpriseHookDomainsAnswering(ctx, deps.answers, domains)
		if ctx.Err() != nil {
			// A check cut short says nothing about the domain controllers.
			return
		}
		var back, gone, away []string
		state.Lock()
		if state.seen == nil {
			state.seen, state.away = map[string]bool{}, map[string]bool{}
		}
		for domain := range state.away {
			if !slices.Contains(domains, domain) {
				delete(state.away, domain)
			}
		}
		for _, domain := range domains {
			switch {
			case slices.Contains(answering, domain):
				if state.away[domain] {
					back = append(back, domain)
				}
				delete(state.away, domain)
				state.seen[domain] = true
			case (state.seen[domain] || deps.awayUnseen) && !state.away[domain]:
				state.away[domain] = true
				gone = append(gone, domain)
			}
		}
		for domain := range state.away {
			away = append(away, domain)
		}
		slices.Sort(away)
		marked := state.marked
		state.Unlock()
		if len(gone) > 0 {
			fmt.Fprintf(stderr, "[hook-guardian] identity: no domain controller of %s answers; the gateway takes the lookups of "+
				"its accounts as failed until one does\n", strings.Join(gone, ", "))
		}
		if len(back) > 0 {
			enterpriseHookFlushAfterReturn(ctx, stderr, deps, back)
		}
		if deps.mark != nil && (len(away) > 0 || marked) {
			if err := deps.mark(dir, away); err != nil {
				fmt.Fprintf(stderr, "[hook-guardian] identity: record the domains whose domain controllers do not answer: %v\n", err)
			} else {
				state.Lock()
				state.marked = len(away) > 0
				state.Unlock()
			}
		}
		if len(away) == 0 || !deps.sleep(ctx, enterpriseHookDirectoryReturnPoll) {
			return
		}
	}
}

// enterpriseHookFlushAfterReturn flushes the directory caches for the
// domains whose domain controllers answer again after an outage, and starts
// their flush backoff, so the return watch (enterpriseHookWatchDirectoryReturn)
// does not flush them again at once.
func enterpriseHookFlushAfterReturn(ctx context.Context, stderr io.Writer, deps enterpriseHookDirectoryReturnDeps, back []string) {
	err := deps.flush(ctx)
	at := deps.now()
	state := &enterpriseHookDirectoryReturnState
	state.Lock()
	if state.flushed == nil {
		state.flushed = map[string]enterpriseHookDirectoryFlush{}
	}
	for _, domain := range back {
		state.flushed[domain] = enterpriseHookDirectoryFlush{at: at, gap: enterpriseHookDirectoryFlushGap}
	}
	state.Unlock()
	names := strings.Join(back, ", ")
	if err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again after an outage, but the directory "+
			"caches were not flushed: %v\n", names, err)
		return
	}
	fmt.Fprintf(stderr, "[hook-guardian] identity: a domain controller of %s answers again after an outage; flushed the directory "+
		"caches, so accounts get their domain groups at their next lookup\n", names)
}
