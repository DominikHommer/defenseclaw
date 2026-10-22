// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Candidate facts of failed directory lookups (unixidentity.UnprovenFactsError).
//
// A lookup that fails only because a directory could not show that it holds
// nothing more of an account still says whose facts they are if it holds
// nothing more: on a "passwd: files sss" host with SSSD stopped, the
// /etc/passwd account with its local groups. Those facts are never applied,
// cached as resolved or recorded, since a directory account of the same uid,
// or a group the directory holds, is not ruled out. The profile matcher only
// compares the profile they select with the one the failed lookup selects
// (withUnprovenCandidate): when both are the same it applies; when they
// differ the request is refused, so neither a weaker default_profile nor the
// local account's profile applies to an account that may be another one.
//
// The local candidate is noted as soon as a lookup starts, from the local
// files alone (unixidentity.LocalCandidateForUID), so a request that stops
// waiting for a slow directory is decided the same way. A uid more than one
// account holds (unixidentity.SharedUIDError) is noted as ambiguous: no
// candidate tells which account it is, and a request is refused whenever an
// assignment could select another profile than the failed lookup's
// (review of r104 W2B, loop round 2). So is a lookup that failed for want of
// a proof and names no candidate (a service before the owner did not
// answer, and the facts still could not be resolved): which account the uid
// is, or its groups, are unknown (review of r104 W2B, loop round 3).
var unprovenFacts = struct {
	sync.Mutex
	entries map[string]unprovenFactsEntry
}{}

type unprovenFactsEntry struct {
	facts useridentity.DirectoryFacts
	// name is the account name of the candidate (its /etc/passwd entry),
	// for a subject that carries none; "" when the lookup gave none.
	name   string
	reason string
	at     time.Time
	// ambiguous marks a uid more than one account holds: facts is empty.
	ambiguous bool
	// unknown marks a lookup that failed for want of a proof and names no
	// candidate: facts is empty.
	unknown bool
}

// unprovenAccounts counts the accounts whose last lookup failed for want of
// a proof less than identityDirectoryTTL ago (status and explain).
func unprovenAccounts(now time.Time) int {
	unprovenFacts.Lock()
	defer unprovenFacts.Unlock()
	n := 0
	for _, entry := range unprovenFacts.entries {
		if now.Sub(entry.at) < identityDirectoryTTL {
			n++
		}
	}
	return n
}

// unprovenFactsFor returns the candidate facts of key's last lookup and why
// it failed, when it failed for want of a proof or for a shared uid, or is
// still running, less than identityDirectoryTTL ago.
func unprovenFactsFor(key string, now time.Time) (unprovenFactsEntry, bool) {
	unprovenFacts.Lock()
	defer unprovenFacts.Unlock()
	entry, ok := unprovenFacts.entries[key]
	if !ok || now.Sub(entry.at) >= identityDirectoryTTL {
		return unprovenFactsEntry{}, false
	}
	return entry, true
}
