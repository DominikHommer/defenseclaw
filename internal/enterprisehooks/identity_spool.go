// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The identity spool.
//
// Some verified directory facts can only be read with privilege: SSSD
// InfoPipe answers root only, the gateway's sandbox hides /proc and user
// homes, and on Windows the token-group cache is SYSTEM-only. The root
// guardian (Linux, macOS) or SYSTEM enumerator (Windows) resolves them for
// each enrolled account and writes one record per account, <uid>.json or
// <SID>.json, in the identity directory under the guardian authorization
// directory: owned by root or SYSTEM and readable by the gateway's group,
// exactly like the AI discovery user-scan spool. The gateway merges a record
// into the facts it resolves itself for the same verified uid or SID.

// IdentitySpoolDirName is the spool directory under the guardian
// authorization directory.
const IdentitySpoolDirName = "identity"

// IdentitySpoolRecordVersion is the record schema version.
const IdentitySpoolRecordVersion = 1

// IdentitySpoolMaxAge is how long the gateway trusts a record (four times the
// 15 minute identity cache lifetime) and how long the guardian keeps the
// record of an account it no longer lists.
const IdentitySpoolMaxAge = time.Hour

// IdentitySpoolKeptUPNMaxAge is how long the guardian keeps a UPN that SSSD
// InfoPipe stopped reporting (KeepVerifiedInfoPipeUPN). Kept without a
// bound, a UPN removed in the directory selected that account's UPN
// profile indefinitely (GAP-1235); a day gives the administrator the status
// and verify warnings of an [ifp] section that lost userPrincipalName
// (GAP-1114) before the accounts fall to the profile their other facts
// select.
const IdentitySpoolKeptUPNMaxAge = 24 * time.Hour

// maxIdentitySpoolRecordBytes bounds one record.
const maxIdentitySpoolRecordBytes = 256 << 10

// UPN sources recorded in IdentitySpoolRecord.UPNSource.
const (
	UPNSourceInfoPipe = "infopipe"
	// UPNSourceInfoPipeKept is a UPN an earlier pass read from InfoPipe,
	// kept because the latest InfoPipe answer for the same account listed no
	// userPrincipalName (KeepVerifiedInfoPipeUPN).
	UPNSourceInfoPipeKept  = "infopipe_kept"
	UPNSourceDerived       = "derived"
	UPNSourceIdentityStore = "identity_store"
	UPNSourceTranslateName = "translate_name"
)

// IdentitySpoolRecord is one account's spool file.
type IdentitySpoolRecord struct {
	Version int `json:"version"`
	// Key is the uid (Linux, macOS) or SID (Windows) the record is for; it
	// must match the file name.
	Key       string    `json:"key"`
	User      string    `json:"user,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	// UPNSource says where Facts.UPN, or the derived Facts.Principal, came
	// from: infopipe, identity_store, translate_name, or derived (the
	// sAMAccountName@REALM fallback; Facts.UPN is then empty).
	UPNSource string `json:"upn_source,omitempty"`
	// UPNKeptSince is when the guardian first kept an InfoPipe UPN that
	// InfoPipe no longer reported (UPNSource infopipe_kept): the UPN goes
	// once it is IdentitySpoolKeptUPNMaxAge old.
	UPNKeptSince time.Time `json:"upn_kept_since,omitzero"`
	// AccountSID is the SID SSSD holds for the uid (Linux), the account's
	// immutable directory identifier; empty for an account without one. An
	// account recreated under the same uid, name and SSSD domain has another
	// SID, so the facts an earlier record carries are another account's:
	// the guardian keeps none of them for it (KeepVerifiedInfoPipeUPN,
	// identitySpoolSameIdentity) and the gateway does not use the record.
	// It is written in the record's extension (identitySpoolRecordExtension),
	// not in the record object, which the 1.0.3 and older gateways decode
	// with unknown fields refused.
	AccountSID string `json:"-"`
	// SSSDDomain is the SSSD domain that holds the uid by InfoPipe
	// Users.FindByID (Linux): the gateway drops a domain, realm and
	// principal of its own that name another domain (mergeSpoolFacts).
	SSSDDomain string `json:"sssd_domain,omitempty"`
	// AccountDomain is the account's DOMAIN\user namespace (its NetBIOS
	// domain, macOS), which DirectoryFacts never serializes: profile
	// matching alone reads it (GAP-0635).
	AccountDomain string                      `json:"account_domain,omitempty"`
	Facts         useridentity.DirectoryFacts `json:"facts"`
	// ConnectorEmails maps "claudecode" and "codex" to the account address
	// the SYSTEM enumerator read from that connector's file in the
	// account's own profile, while ai_discovery.include_user_email is on
	// (Windows). The gateway service cannot read Claude Code's file, which
	// lives in the profile root (GAP-1025).
	ConnectorEmails map[string]string `json:"connector_emails,omitempty"`
}

// identitySpoolRecordExtension holds the facts a record carries that the
// gateways and guardians of 1.0.3 and older do not know. They decode the
// record object with unknown fields refused, so a new field in it made a
// gateway still running beside an upgraded guardian (during the package
// upgrade, or after a rollback) drop every record that had one, and an
// account assigned by the UPN only the record holds fell to the default
// profile. The extension is a second JSON object after the record object
// in the same file, written in the same atomic replace: those builds read
// the first object only and stop there. It is decoded without refusing
// unknown fields, so a later build can add facts to it the same way.
type identitySpoolRecordExtension struct {
	AccountSID string `json:"account_sid,omitempty"`
}

// identitySpoolClockSlack is how far in the future a record may be dated
// before the wall clock counts as stepped back.
const identitySpoolClockSlack = time.Minute

// IdentitySpoolStale reports whether the records in dir look older than
// fresh to a reader of the wall clock: any record is older than fresh, or
// dated more than a minute in the future. The gateway trusts a
// record by its wall-clock age, so after a clock step (an NTP correction, a
// resume from suspend) every record looked over an hour old, or the records
// written under a slow clock did once it was corrected, and the accounts
// assigned by UPN fell to the default profile until the guardian's next
// interval (GAP-0921). oldest is the time of the oldest record, zero for
// none, and key its uid or SID; when only a record dated in the future makes
// the spool stale, they are that record's time and key instead, so the
// account named is the one at fault (GAP-1116).
func IdentitySpoolStale(dir string, now time.Time, fresh time.Duration) (oldest time.Time, key string, stale bool) {
	if dir == "" {
		return time.Time{}, "", false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}, "", false
	}
	var futureAt time.Time
	futureKey := ""
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".json")
		// Only the accounts' records count: the guardian's other files
		// (DirectoryUnreachableFile) are rewritten or removed on their own.
		if entry.IsDir() || !ok || !validIdentitySpoolKey(name) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		written := info.ModTime()
		if oldest.IsZero() || written.Before(oldest) {
			oldest, key = written, name
		}
		if written.Sub(now) > identitySpoolClockSlack && (futureKey == "" || written.After(futureAt)) {
			futureAt, futureKey = written, name
		}
	}
	switch {
	case oldest.IsZero():
		return time.Time{}, "", false
	case now.Sub(oldest) > fresh:
		return oldest, key, true
	case futureKey != "":
		return futureAt, futureKey, true
	}
	return oldest, key, false
}

// IdentitySpoolDir is the spool directory for a guardian authorization
// directory.
func IdentitySpoolDir(authorizationDir string) string {
	if strings.TrimSpace(authorizationDir) == "" {
		return ""
	}
	return filepath.Join(authorizationDir, IdentitySpoolDirName)
}

// ReadIdentitySpoolRecord reads the record for key from dir. trust validates
// the file (root- or SYSTEM-owned, not writable by others) before it is
// opened. A missing record is os.ErrNotExist.
func ReadIdentitySpoolRecord(dir, key string, trust func(path, label string) error) (IdentitySpoolRecord, error) {
	var record IdentitySpoolRecord
	key = strings.TrimSpace(key)
	if dir == "" || !validIdentitySpoolKey(key) {
		return record, os.ErrNotExist
	}
	path := filepath.Join(dir, key+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxIdentitySpoolRecordBytes {
		return record, errors.New("identity spool record is not a regular file within the size limit")
	}
	if trust != nil {
		if err := trust(path, "identity spool record"); err != nil {
			return record, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxIdentitySpoolRecordBytes+1))
	if err != nil {
		return record, err
	}
	return ParseIdentitySpoolRecord(data, key)
}

// ParseIdentitySpoolRecord decodes a record, and its extension when one
// follows it, and checks it names key.
func ParseIdentitySpoolRecord(data []byte, key string) (IdentitySpoolRecord, error) {
	var record IdentitySpoolRecord
	if len(data) > maxIdentitySpoolRecordBytes {
		return record, errors.New("identity spool record exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("parse identity spool record: %w", err)
	}
	if rest := bytes.TrimSpace(data[decoder.InputOffset():]); len(rest) > 0 {
		var extension identitySpoolRecordExtension
		extensionDecoder := json.NewDecoder(bytes.NewReader(rest))
		if err := extensionDecoder.Decode(&extension); err != nil {
			return record, fmt.Errorf("parse identity spool record extension: %w", err)
		}
		if extensionDecoder.More() {
			return record, errors.New("identity spool record has data after its extension")
		}
		record.AccountSID = strings.TrimSpace(extension.AccountSID)
	}
	if record.Version != IdentitySpoolRecordVersion {
		return record, fmt.Errorf("unsupported identity spool record version %d", record.Version)
	}
	if !strings.EqualFold(record.Key, key) {
		return record, errors.New("identity spool record names another account")
	}
	for connector, email := range record.ConnectorEmails {
		if (connector != "claudecode" && connector != "codex") || !useridentity.ValidEmail(email) {
			return record, errors.New("identity spool record names an invalid connector address")
		}
	}
	record.Facts.Assurance = useridentity.AssuranceVerified
	return record, nil
}

// KeepLastKnownUPN carries the UPN of the account's previous record into a
// fresh record that resolved none, with the principal it gave. Windows
// resolves a UPN only while the user is signed in, so without it a signed-out
// account's record fell back to account@REALM and the account showed two
// principals (GAP-0284). The SID or uid is the record key, so the previous
// record is the same account.
func KeepLastKnownUPN(record, previous IdentitySpoolRecord) IdentitySpoolRecord {
	if record.Facts.UPN != "" || previous.Facts.UPN == "" || !strings.EqualFold(record.Key, previous.Key) {
		return record
	}
	record.Facts.UPN = previous.Facts.UPN
	record.Facts.Principal = previous.Facts.UPN
	record.UPNSource = previous.UPNSource
	if record.Facts.Domain == "" {
		record.Facts.Domain = previous.Facts.Domain
	}
	return record
}

// KeepVerifiedInfoPipeUPN carries the UPN an earlier pass read from SSSD
// InfoPipe into a fresh record whose InfoPipe answer listed no
// userPrincipalName. An answer without the attribute is not a verified
// change: it is what InfoPipe says once the [ifp] user_attributes of
// sssd.conf lose userPrincipalName (a hand edit, or a repair that rewrites
// the file). Rewriting the record as derived sent every account a users
// assignment selects by UPN to the default profile within one guardian pass
// (GAP-1114). It keeps the UPN only for the same account in the same SSSD
// domain, under the same name. A uid, name and domain can all be reused by
// an account recreated in the directory, so the account must also be shown
// to be the same one: by its SID (AccountSID) when both records have one,
// and otherwise by the directory itself (bind): a previous record a build
// before 1.0.4 wrote has no SID, and an account of a directory without SIDs
// has none. bind answers whether the directory gives the UPN to this
// account now (UPNBindingBound: kept), to another account or to none
// (UPNBindingOther: the UPN goes), or did not answer (UPNBindingUnknown).
// A lookup that did not answer proves nothing either way, so the UPN the
// earlier pass proved stays, as it did before the SID was recorded, but the
// record carries no SID that pass: the next pass asks again, and only an
// answer binds the UPN to the SID. Two different SIDs are another account:
// the UPN goes. It marks a kept UPN infopipe_kept so status and verify can
// say why. It
// keeps it for IdentitySpoolKeptUPNMaxAge from the first pass that kept it
// (UPNKeptSince): a UPN removed in the directory stayed trusted for as long
// as the guardian ran (GAP-1235). A kept record an older build wrote
// without UPNKeptSince starts the bound at this pass.
func KeepVerifiedInfoPipeUPN(record, previous IdentitySpoolRecord, bind func(upn string) UPNBinding) (IdentitySpoolRecord, bool) {
	if record.Facts.UPN != "" || previous.Facts.UPN == "" ||
		(previous.UPNSource != UPNSourceInfoPipe && previous.UPNSource != UPNSourceInfoPipeKept) ||
		!strings.EqualFold(record.Key, previous.Key) || record.User == "" || !strings.EqualFold(record.User, previous.User) ||
		record.SSSDDomain == "" || !strings.EqualFold(record.SSSDDomain, previous.SSSDDomain) {
		return record, false
	}
	unbound := false
	switch {
	case record.AccountSID != "" && previous.AccountSID != "":
		if !strings.EqualFold(record.AccountSID, previous.AccountSID) {
			return record, false
		}
	default:
		binding := UPNBindingUnknown
		if bind != nil {
			binding = bind(previous.Facts.UPN)
		}
		switch binding {
		case UPNBindingOther:
			return record, false
		case UPNBindingUnknown:
			unbound = true
		}
	}
	since := previous.UPNKeptSince
	if previous.UPNSource != UPNSourceInfoPipeKept || since.IsZero() || since.After(record.UpdatedAt) {
		since = record.UpdatedAt
	}
	if record.UpdatedAt.Sub(since) >= IdentitySpoolKeptUPNMaxAge {
		return record, false
	}
	record.Facts.UPN = previous.Facts.UPN
	record.Facts.Principal = previous.Facts.UPN
	record.Facts.Source = previous.Facts.Source
	record.UPNSource = UPNSourceInfoPipeKept
	record.UPNKeptSince = since
	if unbound {
		record.AccountSID = ""
	}
	return record, true
}

// UPNBinding is what the directory answers about a UPN an earlier pass
// verified for an account (KeepVerifiedInfoPipeUPN).
type UPNBinding int

const (
	// UPNBindingUnknown: the lookup failed or timed out, or was not asked.
	UPNBindingUnknown UPNBinding = iota
	// UPNBindingBound: the directory gives the UPN to the account now.
	UPNBindingBound
	// UPNBindingOther: the directory gives the UPN to another account, or
	// to none.
	UPNBindingOther
)

// ReadIdentitySpoolRecords reads at most limit records of dir, in file name
// order, skipping any that do not parse or that trust refuses.
func ReadIdentitySpoolRecords(dir string, trust func(path, label string) error, limit int) []IdentitySpoolRecord {
	if dir == "" || limit <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var records []IdentitySpoolRecord
	for _, entry := range entries {
		key, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || entry.IsDir() || !validIdentitySpoolKey(key) {
			continue
		}
		if record, err := ReadIdentitySpoolRecord(dir, key, trust); err == nil {
			if records = append(records, record); len(records) == limit {
				break
			}
		}
	}
	return records
}

// MarshalIdentitySpoolRecord serializes a record: the record object, and
// its extension on the next line when it has one.
func MarshalIdentitySpoolRecord(record IdentitySpoolRecord) ([]byte, error) {
	record.Version = IdentitySpoolRecordVersion
	data, err := json.Marshal(record)
	if err != nil || record.AccountSID == "" {
		return data, err
	}
	extension, err := json.Marshal(identitySpoolRecordExtension{AccountSID: record.AccountSID})
	if err != nil {
		return nil, err
	}
	return append(append(data, '\n'), extension...), nil
}

// validIdentitySpoolKey accepts a decimal uid or a SID.
func validIdentitySpoolKey(key string) bool {
	if key == "" || len(key) > 184 {
		return false
	}
	if strings.HasPrefix(strings.ToUpper(key), "S-1-") {
		for i := 4; i < len(key); i++ {
			if c := key[i]; !(c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(key); i++ {
		if key[i] < '0' || key[i] > '9' {
			return false
		}
	}
	return true
}

// writeIdentitySpoolFile replaces dir/name atomically with its final mode
// and ownership set before the rename.
func writeIdentitySpoolFile(dir, name string, record IdentitySpoolRecord, setOwnership func(string) error) error {
	data, err := MarshalIdentitySpoolRecord(record)
	if err != nil {
		return err
	}
	return writeSpoolBytes(dir, name, ".identity-*", data, setOwnership)
}

// writeSpoolBytes replaces dir/name with data atomically, with its final
// mode and ownership set before the rename.
func writeSpoolBytes(dir, name, pattern string, data []byte, setOwnership func(string) error) error {
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o640)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil && setOwnership != nil {
		err = setOwnership(tmpName)
	}
	if err == nil {
		err = os.Rename(tmpName, filepath.Join(dir, name))
	}
	return err
}
