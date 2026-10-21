// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The protected session record (GAP-0352).
//
// On a standalone host the gateway keeps each agent session's foreign-hook
// state in its private data directory (ApplyForeignHookSession). When the
// gateway is stopped, restarting or not answering and the administrator
// chose fail mode open, a guarded connector's hook must still not allow a
// session the gateway blocked: the agent may run a hook it loaded when the
// session started, even after its file was deleted. So after every session
// exchange the gateway also writes its answer for the session and for the
// agent process (blocked, or the allow that clears a block) into a record
// the user can read but not change:
//
//   - Linux and macOS: <HookSessionDir>/<identity digest>/, where
//     HookSessionDir is created by the root lifecycle (ensure) and owned by
//     the service account (mode 0711), and the per-user folder is created by
//     the gateway (service account, mode 0700) with one access-list entry
//     that lets only that uid read it (a POSIX ACL on Linux, a macOS ACL
//     entry). The records in it are 0644.
//   - Windows: %ProgramData%\Cisco\DefenseClaw-HookSessions\<digest>\,
//     created by the SYSTEM lifecycle; the gateway creates the per-user
//     folder with a protected DACL (SYSTEM and Administrators full, the
//     gateway service modify, that user read).
//
// During such an outage the hook reads the record of its own account after
// it checked that every path element is a real folder or file that only
// root/SYSTEM, Administrators or the gateway service can change. The call
// is allowed only when a record proves that the gateway did not block the
// agent process (or, when the process cannot be named, the session) and no
// record blocks it. A missing, unreadable, untrusted or corrupt record
// blocks. The guardian deletes an account's records for a connector when it
// removes one of its hooks, because the gateway then denies the agent
// processes that started before the removal.

const (
	// publishedSessionVersion is the record schema.
	publishedSessionVersion = 1
	// publishedSessionRecordLimit bounds one record.
	publishedSessionRecordLimit = 8 << 10
	// publishedSessionReasonLimit bounds the gateway reason a record keeps.
	publishedSessionReasonLimit = 2048
	// publishedSessionDirLimit bounds the records kept per account. A
	// record pruned past it reads as missing, which blocks.
	publishedSessionDirLimit = 1024
)

// ErrPublishedSessionUnavailable is a protected session record that does
// not prove the session unblocked: missing, unreadable, untrusted or
// corrupt.
var ErrPublishedSessionUnavailable = errors.New("protected foreign-hook session record unavailable")

// PublishedSessionRecord is the gateway's last answer for one agent process
// ("p") or session ("s") of one connector.
type PublishedSessionRecord struct {
	Version   int    `json:"v"`
	Connector string `json:"connector"`
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Blocked   bool   `json:"blocked"`
	Reason    string `json:"reason,omitempty"`
	At        string `json:"at"`
}

// PublishedSessionTrust names the accounts besides root/SYSTEM and
// Administrators that may own and write the protected record: the gateway
// service uid (Linux, macOS; from the root-owned runtime descriptor) or
// service account (Windows).
type PublishedSessionTrust struct {
	ServiceUID     int
	ServiceAccount string
}

// PublishedSessionIdentityDir is the folder of one account below root: the
// first 20 bytes of the SHA-256 of the canonical account identity (a
// decimal uid or an upper-case SID), the digest the gateway's private
// session store uses.
func PublishedSessionIdentityDir(root, identity string) (string, bool) {
	canonical, ok := connector.CanonicalUserScopedIdentity(identity)
	root = strings.TrimSpace(root)
	if !ok || root == "" || !filepath.IsAbs(root) {
		return "", false
	}
	return filepath.Join(filepath.Clean(root), sha256Hex([]byte(canonical))[:40]), true
}

// PublishedSessionRecordPath is the protected record of one agent process
// (kind "p") or session (kind "s") of a connector for identity under root.
func PublishedSessionRecordPath(root, identity, connectorName, kind, id string) (string, bool) {
	dir, ok := PublishedSessionIdentityDir(root, identity)
	if !ok || !publishedSessionConnector(connectorName) || (kind != sessionKindProcess && kind != sessionKindSession) || id == "" {
		return "", false
	}
	return publishedSessionPath(dir, connectorName, kind, id), true
}

func publishedSessionPath(dir, connectorName, kind, id string) string {
	name := connectorName + "-" + kind + "-" + sha256Hex([]byte(connectorName + "\x00" + kind + "\x00" + id))[:40] + ".json"
	return filepath.Join(dir, name)
}

// publishedSessionConnector is a connector name that is safe in a record
// file name.
func publishedSessionConnector(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// PublishForeignHookSessionDecision writes the gateway's answer for one
// session exchange into the protected record of identity under root: a
// denial records the agent process and the session as blocked, an allow
// records them as not blocked (which clears an earlier block). A denial
// that cannot be written removes the earlier record, so it never keeps
// proving the session unblocked. root missing is not an error: the hook
// then finds no record and blocks during an outage.
func PublishForeignHookSessionDecision(root, identity string, key SessionKey, decision GuardDecision, now time.Time) error {
	if strings.TrimSpace(root) == "" {
		return nil
	}
	name := strings.TrimSpace(key.Connector)
	if !key.valid() || !publishedSessionConnector(name) {
		return fmt.Errorf("invalid session key")
	}
	dir, ok := PublishedSessionIdentityDir(root, identity)
	if !ok {
		return fmt.Errorf("invalid caller identity")
	}
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	canonical, _ := connector.CanonicalUserScopedIdentity(identity)
	ensureErr := publishedSessionPrepare(root, dir, canonical)
	if now.IsZero() {
		now = time.Now()
	}
	record := PublishedSessionRecord{
		Version:   publishedSessionVersion,
		Connector: name,
		Blocked:   decision.Deny,
		At:        now.UTC().Format(time.RFC3339),
	}
	if decision.Deny {
		record.Reason = clipPublishedReason(decision.Reason)
	}
	var errs []error
	if ensureErr != nil {
		errs = append(errs, ensureErr)
	}
	created := false
	for _, entry := range []struct{ kind, id string }{{sessionKindProcess, key.Process}, {sessionKindSession, key.Session}} {
		if entry.id == "" {
			continue
		}
		path := publishedSessionPath(dir, name, entry.kind, entry.id)
		if ensureErr != nil {
			// A folder that is not ours is not written to; a blocked answer
			// must still not leave an allow behind.
			if decision.Deny {
				if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
					errs = append(errs, err)
				}
			}
			continue
		}
		record.Kind, record.ID = entry.kind, entry.id
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			created = true
		}
		if err := writePublishedSessionRecord(path, record); err != nil {
			errs = append(errs, err)
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	if created && ensureErr == nil {
		prunePublishedSessionRecords(dir, now)
	}
	return errors.Join(errs...)
}

// RemovePublishedForeignHookSessions deletes the protected records of
// identity for connectors. The guardian calls it after it removed a hook of
// one of them, as root or SYSTEM: the gateway denies every agent process of
// the connector that started before the removal, so no earlier allow may
// stand for an outage.
func RemovePublishedForeignHookSessions(root, identity string, connectors []string) error {
	dir, ok := PublishedSessionIdentityDir(root, identity)
	if !ok {
		return nil
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		for _, name := range connectors {
			name = strings.ToLower(strings.TrimSpace(name))
			if publishedSessionConnector(name) && strings.HasPrefix(entry.Name(), name+"-") {
				if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
					errs = append(errs, err)
				}
				break
			}
		}
	}
	return errors.Join(errs...)
}

// CheckPublishedForeignHookSession decides a guarded call during a gateway
// outage from the protected record of identity under root. It returns the
// scan's decision when a trusted record proves the agent process (or, when
// the process cannot be named, the session) not blocked and no record
// blocks it, a denial with the gateway's reason when a record blocks it,
// and ErrPublishedSessionUnavailable when the record proves neither. trust
// checks a record path and every folder above it (ValidatePublishedSessionPath
// in production).
func CheckPublishedForeignHookSession(root, identity string, key SessionKey, decision GuardDecision, trust func(path string) error) (GuardDecision, error) {
	name := strings.TrimSpace(key.Connector)
	dir, ok := PublishedSessionIdentityDir(root, identity)
	if !ok || !key.valid() || !publishedSessionConnector(name) || trust == nil {
		return decision, ErrPublishedSessionUnavailable
	}
	proven := false
	for _, entry := range []struct{ kind, id string }{{sessionKindProcess, key.Process}, {sessionKindSession, key.Session}} {
		if entry.id == "" {
			continue
		}
		path := publishedSessionPath(dir, name, entry.kind, entry.id)
		record, exists, err := readPublishedSessionRecord(path, trust)
		if err != nil {
			return decision, fmt.Errorf("%w: %v", ErrPublishedSessionUnavailable, err)
		}
		if !exists {
			continue
		}
		if record.Version != publishedSessionVersion || record.Connector != name || record.Kind != entry.kind || record.ID != entry.id {
			return decision, fmt.Errorf("%w: %s does not belong to this agent session", ErrPublishedSessionUnavailable, path)
		}
		if _, err := time.Parse(time.RFC3339, record.At); err != nil {
			return decision, fmt.Errorf("%w: %s has no valid time", ErrPublishedSessionUnavailable, path)
		}
		if record.Blocked {
			return publishedBlockDecision(decision, name, record), nil
		}
		// The process record is the proof when the process is named: the
		// gateway carries a block of the process to every session it runs.
		if entry.kind == sessionKindProcess || key.Process == "" {
			proven = true
		}
	}
	if !proven {
		return decision, ErrPublishedSessionUnavailable
	}
	return decision, nil
}

// publishedBlockDecision denies a call the gateway's record blocks, with the
// gateway's own reason when it kept one.
func publishedBlockDecision(decision GuardDecision, connectorName string, record PublishedSessionRecord) GuardDecision {
	reason := strings.TrimSpace(record.Reason)
	if !strings.HasPrefix(reason, foreignHookBlockedPrefix) {
		reason = foreignHookBlockedPrefix + " the DefenseClaw gateway blocked this agent session's " + connectorName +
			" tool calls, and it is not running to clear the block. Retry when the DefenseClaw gateway is running; if the block continues, remove any unapproved hook and restart the agent."
	}
	decision.Deny = true
	decision.Reason = reason
	decision.Findings = append([]Finding{{
		Connector: connectorName,
		Reason:    "blocked by the gateway's protected session record",
	}}, decision.Findings...)
	return decision
}

// foreignHookBlockedPrefix starts every foreign-hook block reason
// (hookexec.ForeignHookBlockedReasonPrefix).
const foreignHookBlockedPrefix = "enterprise_foreign_hook_blocked:"

func clipPublishedReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(reason))
	if len(reason) <= publishedSessionReasonLimit {
		return reason
	}
	cut := publishedSessionReasonLimit
	for cut > 0 && (reason[cut]&0xc0) == 0x80 {
		cut--
	}
	return reason[:cut]
}

// readPublishedSessionRecord reads one record after trust accepted it and
// every folder above it. A missing record does not exist; anything else
// that cannot be checked, read or decoded is an error.
func readPublishedSessionRecord(path string, trust func(string) error) (PublishedSessionRecord, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		// The folders above must be trusted for "missing" to mean missing;
		// either way the record proves nothing.
		return PublishedSessionRecord{}, false, nil
	} else if err != nil {
		return PublishedSessionRecord{}, true, err
	}
	if err := trust(path); err != nil {
		return PublishedSessionRecord{}, true, err
	}
	data, exists, err := readGuardFileLimit(path, publishedSessionRecordLimit)
	if err != nil {
		return PublishedSessionRecord{}, true, err
	}
	if !exists {
		return PublishedSessionRecord{}, false, nil
	}
	var record PublishedSessionRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return PublishedSessionRecord{}, true, fmt.Errorf("%s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PublishedSessionRecord{}, true, fmt.Errorf("%s: trailing content", path)
	}
	return record, true, nil
}

// writePublishedSessionRecord replaces one record atomically in its folder.
func writePublishedSessionRecord(path string, record PublishedSessionRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) > publishedSessionRecordLimit {
		return fmt.Errorf("session record too large")
	}
	dir := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := publishedSessionFileMode(tmp); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	// A hook that is reading the record holds it open; on Windows that
	// refuses the replace for a moment.
	for attempt := 0; ; attempt++ {
		err := os.Rename(name, path)
		if err == nil {
			return nil
		}
		if attempt == 4 {
			_ = os.Remove(name)
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// prunePublishedSessionRecords removes records older than sessionRecordTTL
// and, past publishedSessionDirLimit, the oldest ones, plus temporary files
// a crashed writer left. A pruned record reads as missing, which blocks.
func prunePublishedSessionRecords(dir string, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type aged struct {
		path string
		mod  time.Time
	}
	var kept []aged
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if strings.HasPrefix(entry.Name(), ".") {
			if now.Sub(info.ModTime()) > time.Hour {
				_ = os.Remove(path)
			}
			continue
		}
		if now.Sub(info.ModTime()) > sessionRecordTTL {
			_ = os.Remove(path)
			continue
		}
		kept = append(kept, aged{path, info.ModTime()})
	}
	if len(kept) <= publishedSessionDirLimit {
		return
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].mod.Before(kept[j].mod) })
	for _, entry := range kept[:len(kept)-publishedSessionDirLimit] {
		_ = os.Remove(entry.path)
	}
}
