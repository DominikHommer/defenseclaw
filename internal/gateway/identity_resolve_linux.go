// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// peerDirectoryLookupTimeout bounds one background resolution (the getent
// calls), well beyond the hot-path budget a waiting request uses. A cold SSSD
// names a group in about 30 ms, one lookup at a time, so the bound grows with
// the largest membership DefenseClaw names (unixidentity.DirectoryLookupBudget,
// GAP-1247); a lookup that still runs out fails as a whole and is retried
// (GAP-0138). `guardrail profile explain` starts this lookup through the
// cache and waits for it at most identityExplainWait; a lookup still running
// then is cached when it ends.
var peerDirectoryLookupTimeout = unixidentity.DirectoryLookupBudget()

// peerIncarnationTimeout bounds the SID lookup that names which directory
// account holds a uid (managedHookPeerAccountIncarnation).
const peerIncarnationTimeout = 10 * time.Second

// managedHookPeerAccountIncarnation names which directory account holds the
// uid of account (unixidentity.AccountIncarnation): the SID SSSD holds for
// it. false when it cannot tell. Tests replace it.
var managedHookPeerAccountIncarnation = func(account unixidentity.Account) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), peerIncarnationTimeout)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return "", false
	}
	return resolver.AccountIncarnation(account.UID, account.Name)
}

// holderSpoolRecord is the guardian's current record of the uid key when it
// was resolved for account, the account that holds the uid now: its name and
// its account incarnation (unixidentity.AccountIncarnation) are the
// account's now. A uid handed from one domain's alice to another domain's
// alice keeps its key and its name, and laid over the second account's
// facts the first one's record gave it the first one's UPN, principal and
// domain, and the profile assigned to them, until the guardian's next pass
// (review of GAP-0551). A record that names no incarnation (an older
// guardian's), or an incarnation that cannot be told now, proves nothing:
// the facts are then the gateway's own, as without a guardian, and the
// cache looks them up again soon (awaitingSpoolUPN).
func holderSpoolRecord(key string, account unixidentity.Account, now time.Time) (enterprisehooks.IdentitySpoolRecord, bool) {
	record, ok := readIdentitySpoolFactsForAccount(key, account.Name, now)
	if !ok || record.AccountIncarnation == "" {
		return enterprisehooks.IdentitySpoolRecord{}, false
	}
	if incarnation, known := managedHookPeerAccountIncarnation(account); !known || incarnation != record.AccountIncarnation {
		return enterprisehooks.IdentitySpoolRecord{}, false
	}
	return record, true
}

// peerLocalCandidate and peerNSSFacts are the two halves of
// resolvePeerDirectoryFacts. Tests replace them.
var (
	peerLocalCandidate = unixidentity.LocalCandidateForUID
	peerNSSFacts       = resolveNSSPeerFacts
)

// resolvePeerDirectoryFacts is resolveNSSPeerFacts. For the profile matcher
// it keeps what the lookup leaves unproven (unprovenFacts):
//   - while the lookup runs, the uid's local candidate from the local files
//     (unixidentity.LocalCandidateForUID), unless an earlier lookup left
//     one: a request that stops waiting for a slow directory is not given a
//     weaker default_profile than the profile of the account's local groups;
//   - after a lookup that failed for want of a proof only, its candidate
//     (unixidentity.UnprovenFactsError), or, when it names none, that the
//     account is unknown, whose requests are refused when an assignment
//     could select another profile;
//   - after a uid more than one account holds (unixidentity.SharedUIDError),
//     that ambiguity, whose requests are refused when an assignment could
//     select another profile;
//   - after any other failure, the local candidate.
//
// A lookup that resolves drops them. Facts are never cached from them.
func resolvePeerDirectoryFacts(key string) (useridentity.DirectoryFacts, error) {
	now := time.Now()
	early, haveEarly := localPeerCandidate(key, now)
	if haveEarly {
		noteUnprovenFacts(key, early, false)
	}
	facts, err := peerNSSFacts(key)
	var (
		unproven *unixidentity.UnprovenFactsError
		shared   *unixidentity.SharedUIDError
	)
	switch {
	case err == nil:
		forgetUnprovenFacts(key)
	case errors.As(err, &unproven) && !unproven.HasCandidate():
		noteUnprovenFacts(key, unprovenFactsEntry{reason: err.Error(), at: time.Now(), unknown: true}, true)
	case errors.As(err, &unproven):
		noteUnprovenFacts(key, unprovenFactsEntry{facts: unproven.Candidate, name: early.name, reason: err.Error(), at: time.Now()}, true)
	case errors.As(err, &shared):
		noteUnprovenFacts(key, unprovenFactsEntry{reason: err.Error(), at: time.Now(), ambiguous: true}, true)
	case haveEarly:
		if !early.ambiguous {
			early.reason = err.Error()
		}
		early.at = time.Now()
		noteUnprovenFacts(key, early, true)
	default:
		forgetUnprovenFacts(key)
	}
	return facts, err
}

// localPeerCandidate is key's local candidate (peerLocalCandidate) as an
// unprovenFacts entry: the local account, or the ambiguity of a uid two
// /etc/passwd entries hold. false when the local files hold no account of
// the uid or cannot be read.
func localPeerCandidate(key string, now time.Time) (unprovenFactsEntry, bool) {
	uid, err := strconv.Atoi(key)
	if err != nil {
		return unprovenFactsEntry{}, false
	}
	name, facts, ok, err := peerLocalCandidate(uid, now)
	var shared *unixidentity.SharedUIDError
	switch {
	case errors.As(err, &shared):
		return unprovenFactsEntry{reason: err.Error(), at: now, ambiguous: true}, true
	case err != nil || !ok:
		return unprovenFactsEntry{}, false
	}
	return unprovenFactsEntry{facts: facts, name: name, at: now,
		reason: fmt.Sprintf("the directory lookup of uid %s has not finished", key)}, true
}

// noteUnprovenFacts keeps entry for key's lookup, for at most
// identityDirectoryMax accounts (the oldest goes first). Without replace it
// keeps an entry key already has within identityDirectoryTTL.
func noteUnprovenFacts(key string, entry unprovenFactsEntry, replace bool) {
	unprovenFacts.Lock()
	defer unprovenFacts.Unlock()
	if unprovenFacts.entries == nil {
		unprovenFacts.entries = map[string]unprovenFactsEntry{}
	}
	if held, known := unprovenFacts.entries[key]; known && !replace && entry.at.Sub(held.at) < identityDirectoryTTL {
		return
	}
	if _, known := unprovenFacts.entries[key]; !known && len(unprovenFacts.entries) >= identityDirectoryMax {
		oldest := ""
		for k, held := range unprovenFacts.entries {
			if oldest == "" || held.at.Before(unprovenFacts.entries[oldest].at) {
				oldest = k
			}
		}
		delete(unprovenFacts.entries, oldest)
	}
	unprovenFacts.entries[key] = entry
}

// resolveNSSPeerFacts resolves a verified uid's facts through NSS and
// merges the guardian's identity spool record for it.
func resolveNSSPeerFacts(key string) (useridentity.DirectoryFacts, error) {
	uid, err := strconv.Atoi(key)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), peerDirectoryLookupTimeout)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	account, err := resolver.LookupUID(uid)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	facts, err := resolver.DirectoryFactsForUID(uid, now)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	record, ok := holderSpoolRecord(key, account, now)
	var spool *enterprisehooks.IdentitySpoolRecord
	if ok {
		spool = &record
	}
	if err := sssdGroupsUnavailable(spool, facts, directoryUnreachable, now); err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	if ok {
		facts = mergeSpoolFacts(facts, record)
	}
	noteGroupDomains(facts.Groups)
	return facts, nil
}
