// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On Windows the SYSTEM enumerator writes one identity record per user in
// its token-group cache: the directory facts it resolves as SYSTEM (the
// identity store, the join state, TranslateNameW) and, only while the user
// has an active desktop session, its token groups. Each SID is followed by
// its DOMAIN\name where the name resolves. The
// gateway's service account cannot read the SYSTEM-only group cache itself.

const (
	// windowsIdentityGroupNameLimit bounds the group SIDs named per user.
	windowsIdentityGroupNameLimit = 128
	// windowsIdentityGroupNameBudget bounds the time spent naming them.
	windowsIdentityGroupNameBudget = 2 * time.Second
)

// WriteWindowsIdentitySpool replaces dir's records with one per user in the
// group cache, except the users in excluded: the accounts the enrollment
// excluded this cycle publish no record, and an earlier one is removed.
// emails holds each account's connector addresses by upper-case
// SID (WindowsConnectorEmails), nil when ai_discovery.include_user_email is
// off. setOwnership applies the guardian authorization protection (SYSTEM
// and Administrators, read for the gateway service) to the directory and to
// each new file before it is renamed into place.
//
// ctx is the enumerator cycle: the pass stops at its deadline, and no
// lookup runs past it. The accounts it did not reach keep their previous
// records, and the next pass starts with the oldest records, so a slow
// directory cannot keep the same accounts from being refreshed.
func WriteWindowsIdentitySpool(ctx context.Context, dir string, cache *WindowsEnrollmentGroupCache, excluded []string,
	emails map[string]map[string]string, setOwnership func(string) error, logf func(string, ...any)) error {
	if dir == "" || cache == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create identity spool: %w", err)
	}
	if setOwnership != nil {
		if err := setOwnership(dir); err != nil {
			return fmt.Errorf("set identity spool protection: %w", err)
		}
	}
	skip := map[string]bool{}
	for _, sid := range excluded {
		skip[strings.ToUpper(strings.TrimSpace(sid))] = true
	}
	type account struct {
		sid, key    string
		previous    IdentitySpoolRecord
		hasPrevious bool
	}
	keep := map[string]bool{}
	accounts := make([]account, 0, len(cache.Users))
	for sid := range cache.Users {
		key := strings.ToUpper(strings.TrimSpace(sid))
		if !validIdentitySpoolKey(key) || skip[key] || keep[strings.ToLower(key+".json")] {
			continue
		}
		keep[strings.ToLower(key+".json")] = true
		entry := account{sid: sid, key: key}
		if previous, err := ReadIdentitySpoolRecord(dir, key, nil); err == nil {
			entry.previous, entry.hasPrevious = previous, true
		}
		accounts = append(accounts, entry)
	}
	// Oldest record first (none at all before any): a pass the cycle deadline
	// stops refreshes the accounts it reached, and the next starts with the
	// rest.
	sort.Slice(accounts, func(i, j int) bool {
		if !accounts[i].previous.UpdatedAt.Equal(accounts[j].previous.UpdatedAt) {
			return accounts[i].previous.UpdatedAt.Before(accounts[j].previous.UpdatedAt)
		}
		return accounts[i].key < accounts[j].key
	})
	var stopped error
	for i, entry := range accounts {
		if err := ctx.Err(); err != nil {
			stopped = fmt.Errorf("identity facts of %d of %d accounts were not refreshed before the enumerator cycle ended; their previous records stay: %w",
				len(accounts)-i, len(accounts), err)
			break
		}
		sid, key := entry.sid, entry.key
		name := key + ".json"
		now := time.Now().UTC()
		facts := windowsIdentityDirectoryFacts(key, 0)
		// The enrollment cache retains last-session groups for enrollment
		// decisions, but they cannot verify the membership of a new SSH or
		// task token. Publish groups only from an active session this cycle.
		facts.GroupsPartial = !cache.SignedIn[sid]
		if !facts.GroupsPartial {
			groupSIDs := cache.Users[sid]
			names := windowsIdentityGroupNames(groupSIDs, windowsIdentityGroupNameLimit, windowsIdentityLookupBudget(ctx, windowsIdentityGroupNameBudget))
			groups := make([]string, 0, 2*len(groupSIDs))
			for i, groupSID := range groupSIDs {
				groups = append(groups, groupSID)
				if i < len(names) && names[i] != groupSID {
					groups = append(groups, names[i])
				}
			}
			facts.Groups = groups
		}
		if facts.ResolvedAt.IsZero() {
			facts.ResolvedAt = now
		}
		record := IdentitySpoolRecord{Key: key, User: windowsIdentitySpoolUser(ctx, key), UpdatedAt: now, Facts: facts,
			ConnectorEmails: emails[key]}
		switch {
		case facts.UPN != "" && facts.Source == useridentity.SourceWindowsIdentityStore:
			record.UPNSource = UPNSourceIdentityStore
		case facts.UPN != "":
			record.UPNSource = UPNSourceTranslateName
		}
		if entry.hasPrevious {
			record = KeepLastKnownUPN(record, entry.previous)
		}
		if err := writeIdentitySpoolFile(dir, name, record, setOwnership); err != nil && logf != nil {
			logf("[hook-enumerator] WARN identity facts for %s: %v", key, err)
		}
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if !keep[strings.ToLower(entry.Name())] {
				_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
			}
		}
	}
	return stopped
}

// windowsIdentityLookupBudget is budget, cut to the time left before ctx's
// deadline.
func windowsIdentityLookupBudget(ctx context.Context, budget time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left < budget {
			return max(left, 0)
		}
	}
	return budget
}

// The directory lookups of a record; tests replace them.
var (
	windowsIdentityDirectoryFacts = useridentity.WindowsDirectoryFacts
	windowsIdentityGroupNames     = useridentity.WindowsGroupNames
)

// windowsIdentitySpoolUser names a record's account DOMAIN\account, as the
// Linux and macOS records name theirs, so a record maps to an account
// without a SID lookup; "" when the SID no longer resolves. While the user
// is signed in with a UPN the LSA names the account by that UPN as typed;
// the record then takes the sAMAccountName the directory translates it to
// (windowsSettledAccountName), which the gateway's service account cannot
// ask for itself (GAP-0382).
func windowsIdentitySpoolUser(ctx context.Context, sid string) string {
	names := windowsIdentityGroupNames([]string{sid}, 1, windowsIdentityLookupBudget(ctx, windowsIdentityGroupNameBudget))
	if len(names) != 1 || names[0] == sid {
		return ""
	}
	domain, account, qualified := strings.Cut(names[0], `\`)
	if qualified && strings.Contains(account, "@") {
		if sam := windowsSettledAccountName(sid, account, domain); sam != "" {
			return domain + `\` + sam
		}
	}
	return names[0]
}

// windowsSettledAccountName is useridentity.SettledWindowsAccountName; tests
// replace it.
var windowsSettledAccountName = useridentity.SettledWindowsAccountName

// windowsConnectorEmailWarned keeps an unreadable connector file from being
// reported at every enumerator cycle.
var windowsConnectorEmailWarned sync.Map

// WindowsConnectorEmails reads, as SYSTEM, the Claude Code and Codex account
// address of each enrolled profile in manifest (ai_discovery.include_user_email),
// keyed by upper-case SID. Each is read from the profile owner's own file and
// only through ordinary folders: a file reached through a link or junction,
// one that cannot be read, or one that is not a regular file gives no address
// and a named warning, logged once per account, connector and reason.
func WindowsConnectorEmails(manifest Manifest, logf func(string, ...any)) map[string]map[string]string {
	out := map[string]map[string]string{}
	seen := map[string]bool{}
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(target.SID))
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		if !validIdentitySpoolKey(key) || home == "." || seen[key] {
			continue
		}
		seen[key] = true
		for _, connector := range []string{"claudecode", "codex"} {
			email, err := windowsProfileConnectorEmail(connector, home)
			if err == nil {
				if out[key] == nil {
					out[key] = map[string]string{}
				}
				out[key][connector] = email
				continue
			}
			if !errors.Is(err, useridentity.ErrEmailFileUnreadable) || logf == nil {
				continue
			}
			if _, warned := windowsConnectorEmailWarned.LoadOrStore(key+"\x00"+connector+"\x00"+err.Error(), true); !warned {
				logf("[hook-enumerator] WARN include_user_email: no %s address for %s: %v", connector, key, err)
			}
		}
	}
	return out
}

// windowsProfileConnectorEmail reads one address; tests replace it.
var windowsProfileConnectorEmail = useridentity.ProfileEmailForConnector
