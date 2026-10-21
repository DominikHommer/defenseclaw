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
var unprovenFacts = struct {
	sync.Mutex
	entries map[string]unprovenFactsEntry
}{}

type unprovenFactsEntry struct {
	facts  useridentity.DirectoryFacts
	reason string
	at     time.Time
}

// unprovenFactsFor returns the candidate facts of key's last lookup and why
// it failed, when it failed for want of a proof less than
// identityDirectoryTTL ago.
func unprovenFactsFor(key string, now time.Time) (useridentity.DirectoryFacts, string, bool) {
	unprovenFacts.Lock()
	defer unprovenFacts.Unlock()
	entry, ok := unprovenFacts.entries[key]
	if !ok || now.Sub(entry.at) >= identityDirectoryTTL {
		return useridentity.DirectoryFacts{}, "", false
	}
	return entry.facts, entry.reason, true
}
