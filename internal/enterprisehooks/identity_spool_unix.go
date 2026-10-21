// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// IdentitySpoolAccount is one enrolled account the guardian resolves.
type IdentitySpoolAccount struct {
	UID  int
	User string
	// Left marks an account the enrollment settings leave out (excluded,
	// exempt, out of the manifest): it is not resolved, and its record
	// goes at once.
	Left bool
}

// checkMacOSRecordUID refuses the Open Directory record dscl returned for an
// account unless its UniqueID is the account's uid. dscl /Search reads by
// short name, so the record can be another account's: its verified identity
// (UPN, domain) was then spooled under this uid (GAP-1075).
func checkMacOSRecordUID(dscl string, uid int) error {
	got, ok := useridentity.MacOSDSCLRecordUID(dscl)
	if !ok {
		return fmt.Errorf("the directory record has no single UniqueID; refusing it for uid %d", uid)
	}
	if got != uid {
		return fmt.Errorf("record belongs to another account (UniqueID %d, not uid %d)", got, uid)
	}
	return nil
}

// identitySpoolLookupTimeout bounds the privileged lookups for one account,
// so one unreachable directory cannot stall the guardian's pass.
const identitySpoolLookupTimeout = 10 * time.Second

// WriteIdentitySpool resolves every account's privileged directory facts
// and replaces dir's records with them: a record per account, and none for
// an account no longer enrolled. setOwnership gives each new file (and the
// directory) the guardian authorization ownership, root:<gateway group>,
// before it is renamed into place, so the gateway never reads a partial or
// unreadable record. A failed privileged lookup keeps a previous verified
// record only while it still names the same account (the gateway checks the
// name again); a newly enrolled or reassigned account gets its basic facts
// until a retry succeeds.
//
// The record of an account missing from accounts goes after a pass in which
// every listed account resolved: the account left the enrollment (excluded,
// out of the manifest) or was deleted, nothing refreshes its record again,
// and status and verify warned identity_records_stale about it 30 minutes
// later (GAP-1113, GAP-1103). Every pass that does not list a young
// directory account's record checks it against the directory
// (identitySpoolDirectoryDeparture): it goes at once when its uid now names
// another account, the same name in another domain or directory, or a local
// account, since its verified identity (UPN, domain) is then another
// account's. Otherwise it stays until it is older than IdentitySpoolMaxAge,
// when the gateway ignores it anyway, unless two successive passes resolved
// an account in that same directory, listed it in neither, and each found
// its uid unresolved; a check that finds the uid still naming the account
// clears the first answer. An outage can remove accounts from one
// directory's enumeration while another still answers, a listing can be
// partial, and one lookup can miss an account its directory still holds;
// removing those records would lose their UPN facts, and a profile assigned
// by UPN would fall to the default (GAP-0145, GAP-1228, GAP-1236). An account
// marked Left goes at once. A failed pass removes nothing else young. The
// checks end with ctx: a record whose check did not finish stays, with its
// mark, for the next pass.
func WriteIdentitySpool(ctx context.Context, dir string, accounts []IdentitySpoolAccount, setOwnership func(string) error,
	logf func(string, ...any)) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create identity spool: %w", err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return fmt.Errorf("harden identity spool: %w", err)
	}
	if setOwnership != nil {
		if err := setOwnership(dir); err != nil {
			return fmt.Errorf("set identity spool ownership: %w", err)
		}
	}
	keep, left := map[string]bool{}, map[string]bool{}
	var passErr error
	answeredDirectories := map[string]bool{}
	for _, account := range accounts {
		if account.UID > 0 && account.Left {
			left[strconv.Itoa(account.UID)+".json"] = true
		}
	}
	for _, account := range accounts {
		if account.UID <= 0 || account.Left || keep[strconv.Itoa(account.UID)+".json"] {
			continue
		}
		name := strconv.Itoa(account.UID) + ".json"
		if account.User != "" {
			if previous, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(account.UID), nil); err == nil &&
				previous.User != "" && !strings.EqualFold(previous.User, account.User) {
				// A UID assigned to a different account must not retain its
				// previous owner's privileged facts if this lookup fails.
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					return fmt.Errorf("remove reassigned identity spool record: %w", err)
				}
			}
		}
		keep[name] = true
		lookupCtx, cancel := context.WithTimeout(ctx, identitySpoolLookupTimeout)
		record, err := identitySpoolCollect(lookupCtx, account, time.Now().UTC())
		cancel()
		if err == nil {
			if previous, readErr := ReadIdentitySpoolRecord(dir, strconv.Itoa(account.UID), nil); readErr == nil {
				binding := UPNBindingUnknown
				bind := func(upn string) UPNBinding {
					// Without a SID on the record it would be checked against,
					// a not-found answer shows only that the directory cannot
					// find the account by UPN (an LDAP directory without a UPN
					// search): it binds nothing either way.
					binding = identitySpoolBindUPN(ctx, account.UID, record.SSSDDomain, upn, record.AccountSID != "")
					return binding
				}
				var kept bool
				record, kept = KeepVerifiedInfoPipeUPN(record, previous, bind)
				switch {
				case logf == nil:
				case kept && binding == UPNBindingUnknown && record.AccountSID == "" && previous.AccountSID == "" && previous.Facts.UPN != "":
					logf("[hook-guardian] identity facts for uid %d: SSSD InfoPipe answered without userPrincipalName, and the directory did not "+
						"answer which account holds the UPN reported before; keeping it, for at most %s, and asking again at the next pass. "+
						"Check that user_attributes in the [ifp] section of sssd.conf lists +userPrincipalName", account.UID, IdentitySpoolKeptUPNMaxAge)
				case !kept && binding == UPNBindingOther:
					logf("[hook-guardian] identity facts for uid %d: SSSD InfoPipe answered without userPrincipalName, and the directory gives "+
						"the UPN reported before to another account or to none; no longer keeping it", account.UID)
				case kept && previous.UPNSource != UPNSourceInfoPipeKept:
					logf("[hook-guardian] identity facts for uid %d: SSSD InfoPipe answered without userPrincipalName; keeping the UPN "+
						"it reported before for at most %s. Check that user_attributes in the [ifp] section of sssd.conf lists +userPrincipalName",
						account.UID, IdentitySpoolKeptUPNMaxAge)
				case !kept && previous.UPNSource == UPNSourceInfoPipeKept && record.Facts.UPN == "":
					logf("[hook-guardian] identity facts for uid %d: SSSD InfoPipe has answered without userPrincipalName for %s; "+
						"no longer keeping the UPN it reported before", account.UID, IdentitySpoolKeptUPNMaxAge)
				}
			}
			err = writeIdentitySpoolFile(dir, name, record, setOwnership)
			if err == nil && identitySpoolDirectoryRecord(record) {
				if key := identitySpoolDirectoryKey(record); key != "" {
					answeredDirectories[key] = true
				}
			}
		} else if record.Key != "" {
			// Keep a previous verified UPN through a transient lookup
			// failure, but only while the facts the lookup did get name the
			// same directory identity: a uid reused by the same name in
			// another domain must not keep the other account's UPN. For a
			// newly enrolled account, still provide its basic NSS facts
			// while the privileged lookup is retried.
			if previous, readErr := ReadIdentitySpoolRecord(dir, strconv.Itoa(account.UID), nil); readErr == nil &&
				identitySpoolSameIdentity(previous, record, false) == identitySpoolDepartureOther {
				err = errors.Join(err, writeIdentitySpoolFile(dir, name, record, setOwnership))
			} else if _, statErr := os.Stat(filepath.Join(dir, name)); errors.Is(statErr, os.ErrNotExist) {
				err = errors.Join(err, writeIdentitySpoolFile(dir, name, record, setOwnership))
			} else if statErr != nil {
				err = errors.Join(err, statErr)
			}
		}
		if err != nil {
			passErr = errors.Join(passErr, fmt.Errorf("uid %d: %w", account.UID, err))
			if logf != nil {
				logf("[hook-guardian] identity facts for uid %d: %v", account.UID, err)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.Join(passErr, fmt.Errorf("read identity spool: %w", err))
	}
	// The marks are read and stored under the lock; the departure lookups
	// run without it. A stored mark map is never changed afterwards.
	identitySpoolUnresolved.Lock()
	unresolvedBefore := identitySpoolUnresolved.byDir[dir]
	identitySpoolUnresolved.Unlock()
	unresolved := map[string]bool{}
	for _, entry := range entries {
		if keep[entry.Name()] {
			continue
		}
		if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) < IdentitySpoolMaxAge && !left[entry.Name()] {
			gone, directory := identitySpoolRecordLeft(dir, entry, answeredDirectories)
			if directory {
				departure := identitySpoolDirectoryDeparture(ctx, dir, entry.Name())
				switch {
				case departure == identitySpoolDepartureOther:
					// The uid now names another account, or the same name in
					// another domain or directory: the record's verified
					// identity is no longer this uid's, whatever the pass or
					// the record's own directory says. It goes now.
				case departure == identitySpoolDepartureStays:
					// The uid still names the record's account: the listing
					// merely omitted it, and an earlier not-found answer was a
					// miss. Its mark goes, also on a failed pass.
					continue
				case passErr != nil:
					unresolved[entry.Name()] = unresolvedBefore[entry.Name()]
					continue
				case !gone:
					continue
				case departure != identitySpoolDepartureNotFound:
					// A check that did not finish shows nothing either way:
					// the mark stays as it was.
					unresolved[entry.Name()] = unresolvedBefore[entry.Name()]
					continue
				case !unresolvedBefore[entry.Name()]:
					// The first not-found answer marks the record; it goes at
					// the next pass that omits it only when that one's check
					// finds the uid unresolved too. One lookup can miss an
					// account its directory still holds. Until then the record
					// ages out (GAP-1236).
					unresolved[entry.Name()] = true
					continue
				}
			} else if passErr != nil || !gone {
				continue
			}
		}
		_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
	}
	identitySpoolUnresolved.Lock()
	defer identitySpoolUnresolved.Unlock()
	for name, marked := range unresolved {
		if !marked {
			delete(unresolved, name)
		}
	}
	if len(unresolved) == 0 {
		delete(identitySpoolUnresolved.byDir, dir)
	} else {
		identitySpoolUnresolved.byDir[dir] = unresolved
	}
	return passErr
}

// identitySpoolCollect is collectIdentitySpoolRecord; tests replace it.
var identitySpoolCollect = collectIdentitySpoolRecord

// identitySpoolBindUPN asks the directory whether it gives upn to the
// account with uid in its SSSD domain sssdDomain (KeepVerifiedInfoPipeUPN);
// notFoundIsOther says a not-found answer means the UPN is no longer this
// account's. Tests replace it.
var identitySpoolBindUPN = bindIdentitySpoolUPN

// identitySpoolDeparture is what the directory shows about the account of a
// young directory record that a pass did not list.
type identitySpoolDeparture int

const (
	// identitySpoolDepartureUnknown: a lookup failed, timed out or was cut
	// short by the pass, or nothing could be compared. It shows nothing: an
	// error is never a deletion.
	identitySpoolDepartureUnknown identitySpoolDeparture = iota
	// identitySpoolDepartureStays: the uid still names the record's account
	// in the record's directory.
	identitySpoolDepartureStays
	// identitySpoolDepartureNotFound: the uid does not resolve. One answer
	// can miss an account its directory still holds (GAP-1236).
	identitySpoolDepartureNotFound
	// identitySpoolDepartureOther: the uid names another account, the same
	// name in another domain or directory, or a local account.
	identitySpoolDepartureOther
)

// identitySpoolDirectoryDeparture looks up the uid of the record name and,
// when it still names the record's account, that account's directory facts,
// and compares them with the record's. The name alone does not bind the
// record: a uid can be reused by the same short name in another domain, and
// the gateway, which checks only the name, would then select a profile by
// the other domain's UPN. The lookups end with ctx and after
// identitySpoolLookupTimeout.
func identitySpoolDirectoryDeparture(ctx context.Context, dir, name string) identitySpoolDeparture {
	key, _ := strings.CutSuffix(name, ".json")
	uid, err := strconv.Atoi(key)
	if err != nil || uid <= 0 || ctx.Err() != nil {
		return identitySpoolDepartureUnknown
	}
	record, err := ReadIdentitySpoolRecord(dir, key, nil)
	if err != nil {
		return identitySpoolDepartureUnknown
	}
	lookupCtx, cancel := context.WithTimeout(ctx, identitySpoolLookupTimeout)
	defer cancel()
	account, err := identityLookupGated(lookupCtx, &identitySpoolDepartureGate, key, func(ctx context.Context) (unixidentity.Account, error) {
		return identitySpoolLookupUID(ctx, uid)
	})
	switch {
	case err != nil && lookupCtx.Err() == nil && unixidentity.IsNotFound(err):
		return identitySpoolDepartureNotFound
	case err != nil:
		return identitySpoolDepartureUnknown
	case account.UID != uid || (record.User != "" && !strings.EqualFold(account.Name, record.User)):
		return identitySpoolDepartureOther
	}
	fresh, err := identityLookupGated(lookupCtx, &identitySpoolDepartureGate, key, func(ctx context.Context) (IdentitySpoolRecord, error) {
		return identitySpoolCollect(ctx, IdentitySpoolAccount{UID: uid, User: account.Name}, time.Now().UTC())
	})
	if lookupCtx.Err() != nil || (err != nil && fresh.Key == "") {
		return identitySpoolDepartureUnknown
	}
	return identitySpoolSameIdentity(record, fresh, err == nil)
}

// identitySpoolSameIdentity compares a record's directory identity with
// fresh, what the directory answers for its uid now; complete says every
// lookup of fresh succeeded. Each fact both name must agree, the account's
// SID first: an account recreated under the same uid, name and domain has
// another SID. A complete
// answer that is no directory account's (the uid is a local account now)
// is another identity; an incomplete one that names nothing to compare
// shows nothing.
func identitySpoolSameIdentity(record, fresh IdentitySpoolRecord, complete bool) identitySpoolDeparture {
	if !identitySpoolDirectoryRecord(record) {
		return identitySpoolDepartureUnknown
	}
	if !identitySpoolDirectoryRecord(fresh) {
		if complete {
			return identitySpoolDepartureOther
		}
		return identitySpoolDepartureUnknown
	}
	compared := false
	for _, pair := range [][2]string{
		{record.AccountSID, fresh.AccountSID},
		{record.SSSDDomain, fresh.SSSDDomain},
		{record.AccountDomain, fresh.AccountDomain},
		{record.Facts.Domain, fresh.Facts.Domain},
		{record.Facts.Realm, fresh.Facts.Realm},
		{string(record.Facts.Directory), string(fresh.Facts.Directory)},
		{record.Facts.UPN, fresh.Facts.UPN},
		{record.Facts.TenantID, fresh.Facts.TenantID},
	} {
		if pair[0] == "" || pair[1] == "" {
			continue
		}
		if !strings.EqualFold(pair[0], pair[1]) {
			return identitySpoolDepartureOther
		}
		compared = true
	}
	if !compared {
		return identitySpoolDepartureUnknown
	}
	return identitySpoolDepartureStays
}

// identitySpoolLookupUID is the guardian's account lookup by uid, bounded by
// ctx; tests replace it.
var identitySpoolLookupUID = func(ctx context.Context, uid int) (unixidentity.Account, error) {
	return unixidentity.Default(ctx).LookupUID(uid)
}

// identitySpoolDepartureGate holds the departure lookups of the passes, by
// uid: a lookup that does not stop with its deadline (an Open Directory or
// NSS call) is left to finish on its own, and until it returns only its own
// account's check is skipped (identityLookupGated).
var identitySpoolDepartureGate identityLookupGate

// identitySpoolUnresolved holds, per spool directory, the young directory
// records whose uid the departure check of the last pass that omitted them
// found unresolved (identitySpoolDepartureNotFound) while their directory
// answered. A listing's omission alone shows nothing, since partial listings
// omit accounts that still exist, and one not-found answer does not show
// that the account left: a lookup can miss it once (GAP-1236). The record
// goes at a second not-found answer in a row; a check that finds the uid
// naming the account again clears the mark. The guardian is one
// long-running process; after a restart the first pass only marks.
var identitySpoolUnresolved = struct {
	sync.Mutex
	byDir map[string]map[string]bool
}{byDir: map[string]map[string]bool{}}

// identitySpoolRecordLeft reports whether a young unlisted record can be
// removed, and whether it is a directory record, which goes only when a
// second pass confirms its account's departure. Directory records leave
// only after their own directory answered; a record without a usable
// directory key stays until it ages out.
func identitySpoolRecordLeft(dir string, entry os.DirEntry, answeredDirectories map[string]bool) (left, directory bool) {
	key, ok := strings.CutSuffix(entry.Name(), ".json")
	if !ok || !entry.Type().IsRegular() || !validIdentitySpoolKey(key) {
		return false, false
	}
	record, err := ReadIdentitySpoolRecord(dir, key, nil)
	if err != nil || !identitySpoolDirectoryRecord(record) {
		return true, false
	}
	name := identitySpoolDirectoryKey(record)
	return name != "" && answeredDirectories[name], true
}

// identitySpoolDirectoryKey uses the SSSD domain that actually held the uid
// when available. The prefixes keep SSSD and other directory namespaces
// separate; an unknown domain cannot justify deleting another record.
func identitySpoolDirectoryKey(record IdentitySpoolRecord) string {
	switch {
	case record.SSSDDomain != "":
		return "sssd:" + strings.ToLower(record.SSSDDomain)
	case record.Facts.Domain != "":
		return "domain:" + strings.ToLower(record.Facts.Domain)
	case record.Facts.Realm != "":
		return "realm:" + strings.ToLower(record.Facts.Realm)
	default:
		return ""
	}
}

// identitySpoolDirectoryRecord reports whether record is a directory
// account's (SSSD, winbind, LDAP, an AD-bound Mac) rather than a local one.
func identitySpoolDirectoryRecord(record IdentitySpoolRecord) bool {
	facts := record.Facts
	if facts.Directory != "" {
		return facts.Directory != useridentity.DirectoryLocal
	}
	return record.SSSDDomain != "" || facts.Realm != "" || facts.Domain != "" || facts.UPN != ""
}

// trustedIdentityTool returns the first root-owned, non-writable candidate.
func trustedIdentityTool(candidates ...string) string {
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() || !rootOwnedChain(candidate) {
			continue
		}
		return candidate
	}
	return ""
}

// boundedOutput trims command output to a sane size.
func boundedOutput(data []byte) string {
	const limit = 64 << 10
	if len(data) > limit {
		data = data[:limit]
	}
	return strings.ToValidUTF8(string(data), "")
}
