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
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
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
//
// The accounts the settings leave out are matched against the rows, the
// eligible accounts and the records already in dir, the identity spool, so
// the record of an account a partial listing omitted goes at once too.
func enterpriseHookIdentitySpoolAccounts(ctx context.Context, stderr io.Writer, dir string,
	run enterpriseHookReconcileRun) ([]enterprisehooks.IdentitySpoolAccount, []string) {
	accounts := []enterprisehooks.IdentitySpoolAccount{}
	keys := []string{}
	seen := map[int]bool{}
	var leftUIDs []int
	// The current exclude_users and exempt_users apply before any row or
	// eligible account: the manifest and eligible-accounts.json the
	// enumerator wrote can be older than them (a later write failed), and an
	// account they still list must not keep its record (left).
	leftOut := enterpriseHookEnrollmentLeftOut(ctx)
	left := map[int]bool{}
	leave := func(uid int) {
		if !left[uid] {
			left[uid] = true
			leftUIDs = append(leftUIDs, uid)
		}
	}
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
		if row.UID <= 0 || seen[row.UID] || left[row.UID] {
			continue
		}
		// The manifest's spelling is not proof of the UID's current name.
		// macOS directory collection also needs this canonical name.
		user := canonicalUser(row.UID)
		if leftOut.has(row.UID, row.User, user) {
			leave(row.UID)
			continue
		}
		seen[row.UID] = true
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
			enrolled := enterprisehooks.ManifestEnrolledAccounts(extra, enterprisehooks.Manifest{Targets: run.Targets})
			for _, account := range extra {
				if !slices.ContainsFunc(enrolled, func(e enterprisehooks.UnixEligibleAccount) bool { return e.UID == account.UID }) {
					leftUIDs = append(leftUIDs, account.UID)
				}
			}
			extra = enrolled
		}
		for _, account := range extra {
			if account.UID <= 0 || seen[account.UID] || left[account.UID] {
				continue
			}
			user := canonicalUser(account.UID)
			if leftOut.has(account.UID, account.User, user) {
				leave(account.UID)
				continue
			}
			seen[account.UID] = true
			accounts = append(accounts, enterprisehooks.IdentitySpoolAccount{UID: account.UID, User: user})
			keys = append(keys, strconv.Itoa(account.UID)+":"+user)
		}
	}
	// The accounts the enrollment settings leave out (excluded, exempt, out
	// of the manifest) lose their record at once. A directory account the
	// pass merely does not list keeps it until the directory shows that it
	// left, since a listing can be partial (GAP-1113, GAP-1236).
	for _, uid := range leftOut.numeric {
		leave(uid)
	}
	for _, record := range enterprisehooks.ReadIdentitySpoolRecords(dir, nil, enterpriseHookLeftOutRecordsMax) {
		if uid, err := strconv.Atoi(record.Key); err == nil && uid > 0 && !seen[uid] && !left[uid] && leftOut.has(uid, record.User) {
			leave(uid)
		}
	}
	for _, uid := range leftUIDs {
		if uid > 0 && !seen[uid] {
			seen[uid] = true
			accounts = append(accounts, enterprisehooks.IdentitySpoolAccount{UID: uid, Left: true})
			// A newly left account changes the keys, so its record goes at
			// the next tick, also when no listing named it before (a
			// partial listing omitted it) and the enrolled keys stay the
			// same.
			keys = append(keys, "left:"+strconv.Itoa(uid))
		}
	}
	return accounts, keys
}

// enterpriseHookLeftOutAccounts is what enterprise.enrollment.exclude_users
// and exempt_users name, matched as the enumerator matches them: an account
// name or its decimal uid. A name is also resolved to its uid, so another
// spelling of the account matches too, and a name that does not resolve
// (the directory does not answer) still matches the name a row, an eligible
// account or an identity record carries.
//
// The names are resolved only when an account the pass would keep is not
// already left out by its uid or one of its spellings, so a host with no
// such account asks the directory nothing. The lookups end with the
// reconcile context and after enterpriseHookLeftOutLookupWait, and a name
// whose earlier lookup has not returned (an Open Directory call that never
// answers) starts no new one (enterprisehooks.LookupStandaloneUserBounded):
// a stalled lookup never holds the guardian's watch loop. A name whose
// lookup does not answer this pass keeps the uid its last answer gave
// (enterpriseHookLeftOutProven), so an exclusion keeps applying through an
// outage; a not-found answer forgets it.
type enterpriseHookLeftOutAccounts struct {
	ctx context.Context
	// numeric holds the entries written as a decimal uid.
	numeric []int
	byUID   map[int]bool
	names   map[string]bool
	// unresolved lists the name entries resolve has not looked up yet.
	unresolved []string
	resolved   bool
}

// enterpriseHookLeftOutLookupWait bounds the name lookups of one call.
var enterpriseHookLeftOutLookupWait = 3 * time.Second

// enterpriseHookLeftOutProven holds the uid each exclude_users or
// exempt_users name last resolved to.
var enterpriseHookLeftOutProven = struct {
	sync.Mutex
	uids map[string]int
}{uids: map[string]int{}}

// enterpriseHookEnrollmentLeftOut reads the current settings' exclude_users
// and exempt_users; their names are resolved on demand (has).
func enterpriseHookEnrollmentLeftOut(ctx context.Context) *enterpriseHookLeftOutAccounts {
	out := &enterpriseHookLeftOutAccounts{ctx: ctx, byUID: map[int]bool{}, names: map[string]bool{}}
	if cfg == nil {
		return out
	}
	for _, entry := range append(slices.Clone(cfg.Enterprise.Enrollment.ExcludeUsers), cfg.Enterprise.Enrollment.ExemptUsers...) {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		out.names[entry] = true
		if uid, err := strconv.Atoi(entry); err == nil {
			if uid > 0 && !out.byUID[uid] {
				out.byUID[uid] = true
				out.numeric = append(out.numeric, uid)
			}
		} else if !slices.Contains(out.unresolved, entry) {
			out.unresolved = append(out.unresolved, entry)
		}
	}
	return out
}

// has reports whether the settings leave out the account with uid, by uid
// or by one of names (its spelling in a row, an eligible account or an
// identity record, its name by uid). It resolves the names the first time
// they are needed.
func (l *enterpriseHookLeftOutAccounts) has(uid int, names ...string) bool {
	if l.byUID[uid] {
		return true
	}
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" && l.names[name] {
			return true
		}
	}
	if !l.resolved {
		l.resolve()
	}
	return l.byUID[uid]
}

// resolve looks the name entries up at once, each at most until the call's
// wait ends.
func (l *enterpriseHookLeftOutAccounts) resolve() {
	l.resolved = true
	if len(l.unresolved) == 0 {
		return
	}
	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	waitCtx, cancel := context.WithTimeout(ctx, enterpriseHookLeftOutLookupWait)
	defer cancel()
	type answer struct {
		uid   int
		found bool
		known bool
	}
	answers := make([]answer, len(l.unresolved))
	var wg sync.WaitGroup
	for i, name := range l.unresolved {
		wg.Add(1)
		go func() {
			defer wg.Done()
			account, err := enterprisehooks.LookupStandaloneUserBounded(waitCtx, name)
			switch {
			case err == nil && account.UID > 0:
				answers[i] = answer{uid: account.UID, found: true, known: true}
			case unixidentity.IsNotFound(err):
				answers[i] = answer{known: true}
			}
		}()
	}
	wg.Wait()
	proven := &enterpriseHookLeftOutProven
	proven.Lock()
	defer proven.Unlock()
	for i, name := range l.unresolved {
		key := strings.ToLower(name)
		switch got := answers[i]; {
		case got.found:
			proven.uids[key] = got.uid
		case got.known:
			delete(proven.uids, key)
		}
		if uid := proven.uids[key]; uid > 0 {
			l.byUID[uid] = true
		}
	}
	l.unresolved = nil
}

// enterpriseHookLeftOutRecordsMax bounds the identity records one pass
// checks against the settings.
const enterpriseHookLeftOutRecordsMax = 4096

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
	accounts, keys := enterpriseHookIdentitySpoolAccounts(ctx, stderr, dir, run)
	enrolled := slices.DeleteFunc(slices.Clone(accounts), func(a enterprisehooks.IdentitySpoolAccount) bool { return a.Left })
	startEnterpriseHookDirectoryReturnWatch(ctx, stderr, dir, enrolled)
	startEnterpriseHookDirectoryReachWatch(ctx, stderr, dir, enrolled)
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
