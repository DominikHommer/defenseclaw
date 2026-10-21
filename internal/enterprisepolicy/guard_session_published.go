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
	"strconv"
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
// Every answer carries the record folder's generation, which the gateway
// read before it read the guardian's removals: the modification time of
// <HookSessionDir>/generation, a file that only root or SYSTEM writes
// (BumpPublishedSessionGeneration). The lifecycle (install, upgrade, repair,
// ensure) bumps it before it changes anything and again once it put the
// folder back, and the guardian bumps it after every removal it recorded.
// A bump makes every allow written before it prove nothing. So no repair,
// upgrade or revocation has to find the records it invalidates, and no
// interleaving with an exchange can leave an allow behind: an exchange that
// read the generation before the guardian's bump stamps its answer with the
// old one, and an exchange that read it after the bump reads removals at
// least as new as the bump. An account that hid, moved back or replayed a
// record while it could change the tree only brings back an answer of an
// earlier generation.
//
// During such an outage the hook allows a call only when all of these hold,
// and blocks otherwise (a lookup, trust or decode failure, a missing or
// untrusted generation file, a clock that moved, anything unexpected):
//
//   - the record of its agent process says not blocked, and the record and
//     every folder above it are real files and folders that only
//     root/SYSTEM, Administrators or the gateway service can change. A
//     session record alone never proves an allow: an agent started during
//     the outage may resume the session ID of an earlier one;
//   - the record carries the current generation, whose file root/SYSTEM or
//     Administrators own;
//   - the answer is at most publishedSessionMaxAge old and dated no later
//     than publishedSessionClockSkew after now;
//   - no record and no deny marker blocks the call, and every record read is
//     still the same file at the end;
//   - no lifecycle run or guardian pass holds the record folder: no hold is
//     in the hold folder (PublishedSessionHoldDir), the one a lifecycle puts
//     there before it replaces or closes the folder and a guardian before
//     it publishes a removal, each removed only once the generation bump
//     after it succeeded (HoldPublishedSessionRecords,
//     HoldPublishedSessionRemoval), and the generation did not change while
//     the hook checked the holds.
//
// A block the gateway decides on its own (a session start that found an
// unapproved hook) bumps no generation: it replaces the record. When the
// record can be neither replaced nor deleted (on Windows the account may
// hold it open for reading without delete sharing), revokePublishedSessionRecord
// overrides it twice, so that no single write decides: it expires the
// record in place (publishedSessionRevokedTime, metadata only: it needs no
// free space, and a reader's sharing mode does not refuse it) and writes its
// deny marker (<record>.deny). Either one denies; only a later allow that
// replaced the record clears both.
//
// No removal state lives in this tree. The guardian's ledger, and an
// account's pending mark (MarkForeignHookRemovalPending) for a removal the
// guardian could not record or whose generation bump failed, are in folders
// no standard user can reach.

const (
	// publishedSessionVersion is the record schema: 2 carries the generation.
	publishedSessionVersion = 2
	// publishedSessionRecordLimit bounds one record.
	publishedSessionRecordLimit = 8 << 10
	// publishedSessionReasonLimit bounds the gateway reason a record keeps.
	publishedSessionReasonLimit = 2048
	// publishedSessionDirLimit bounds the records kept per account. A
	// record pruned past it reads as missing, which blocks.
	publishedSessionDirLimit = 1024
	// publishedSessionDenySuffix replaces a record's .json for its deny
	// marker.
	publishedSessionDenySuffix = ".deny"
	// PublishedSessionGenerationFile is the generation file in the record
	// folder (BumpPublishedSessionGeneration).
	PublishedSessionGenerationFile = "generation"
	// publishedSessionMaxAge is the oldest answer the hook accepts during an
	// outage, by the record's time and by its modification time. The
	// gateway writes the record again at every exchange, so an agent in use
	// keeps a fresh one; an outage that lasts longer blocks.
	publishedSessionMaxAge = 15 * time.Minute
	// publishedSessionClockSkew is how far after now the hook still accepts
	// a record's time and modification time. The gateway and the hook read
	// the same clock, so this only covers a small step back of it.
	publishedSessionClockSkew = time.Minute
)

// publishedSessionRevokedTime is the modification time a revocation gives a
// record it cannot delete: far older than publishedSessionMaxAge.
var publishedSessionRevokedTime = time.Unix(0, 0).UTC()

// publishedSessionRename replaces a record, publishedSessionRemove deletes
// one, publishedSessionExpire sets its modification time to
// publishedSessionRevokedTime, publishedSessionCreate creates a deny marker
// and publishedSessionSetTime sets the generation file's modification time
// (replaceable in tests, which stand in for a Windows reader that holds a
// record open without delete sharing, a full volume, and a file system that
// keeps a time it was not given).
var (
	publishedSessionRename = os.Rename
	publishedSessionRemove = os.Remove
	publishedSessionExpire = expirePublishedSessionRecord
	publishedSessionCreate = func(name string) (*os.File, error) {
		return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	}
	publishedSessionSetTime = setPublishedSessionTime
)

// publishedSessionGenerationOwner checks the owner of the generation file
// (checkPublishedSessionGenerationOwner; replaceable in tests, which do not
// run as root).
var publishedSessionGenerationOwner = checkPublishedSessionGenerationOwner

// ErrPublishedSessionUnavailable is a protected session record that does
// not prove the session unblocked: missing, unreadable, untrusted, corrupt,
// stale or of an earlier generation.
var ErrPublishedSessionUnavailable = errors.New("protected foreign-hook session record unavailable")

// PublishedSessionRecord is the gateway's last answer for one agent process
// ("p") or session ("s") of one connector, with the generation of the
// record folder it was decided under.
type PublishedSessionRecord struct {
	Version    int    `json:"v"`
	Connector  string `json:"connector"`
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	Blocked    bool   `json:"blocked"`
	Reason     string `json:"reason,omitempty"`
	At         string `json:"at"`
	Generation string `json:"gen,omitempty"`
}

// PublishedSessionTrust names the accounts besides root/SYSTEM and
// Administrators that may own and write the protected record: the gateway
// service uid (Linux, macOS; from the root-owned runtime descriptor) or
// service account (Windows). The generation file is never the service's.
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

// PublishedSessionGenerationPath is the generation file of the record
// folder root.
func PublishedSessionGenerationPath(root string) (string, bool) {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return "", false
	}
	return filepath.Join(filepath.Clean(root), PublishedSessionGenerationFile), true
}

func publishedSessionPath(dir, connectorName, kind, id string) string {
	name := connectorName + "-" + kind + "-" + sha256Hex([]byte(connectorName + "\x00" + kind + "\x00" + id))[:40] + ".json"
	return filepath.Join(dir, name)
}

// publishedSessionDenyPath is the deny marker of the record at path.
func publishedSessionDenyPath(path string) string {
	return strings.TrimSuffix(path, ".json") + publishedSessionDenySuffix
}

// publishedSessionConnector is a connector name that is safe in a record
// file name.
func publishedSessionConnector(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// PublishForeignHookSessionDecision writes the gateway's answer for one
// session exchange into the protected record of identity under root: a
// denial records the agent process and the session as blocked, an allow
// records them as not blocked (which clears an earlier block, and the deny
// marker a revocation left). generation is the record folder's generation
// that the gateway read before it read the guardian's removals
// (PublishedSessionGeneration); an allow without one proves nothing. A
// denial that cannot be written revokes the earlier record
// (revokePublishedSessionRecord), so it never keeps proving the session
// unblocked. root missing is not an error: the hook then finds no record
// and blocks during an outage.
func PublishForeignHookSessionDecision(root, identity string, key SessionKey, decision GuardDecision, generation string, now time.Time) error {
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
		Version:    publishedSessionVersion,
		Connector:  name,
		Blocked:    decision.Deny,
		At:         now.UTC().Format(time.RFC3339),
		Generation: generation,
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
		record.Kind, record.ID = entry.kind, entry.id
		if ensureErr != nil {
			// A folder that is not ours is not written to; a blocked answer
			// must still not leave an allow behind.
			if decision.Deny {
				if err := revokePublishedSessionRecord(path, record); err != nil {
					errs = append(errs, err)
				}
			}
			continue
		}
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			created = true
		}
		if err := writePublishedSessionRecord(path, record); err != nil {
			errs = append(errs, err)
			if decision.Deny {
				if err := revokePublishedSessionRecord(path, record); err != nil {
					errs = append(errs, err)
				}
			} else if err := publishedSessionRemove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				// The earlier answer stays: an allow, or a block that
				// still denies.
				errs = append(errs, err)
			}
			continue
		}
		if !decision.Deny {
			// The record now holds the allow, so the marker of an earlier
			// revocation goes. One that cannot be removed keeps denying.
			if err := publishedSessionRemove(publishedSessionDenyPath(path)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	if created && ensureErr == nil {
		prunePublishedSessionRecords(dir, now)
	}
	return errors.Join(errs...)
}

// revokePublishedSessionRecord makes the record at path stop proving its
// agent process or session unblocked. It deletes the record; when that
// fails (on Windows a reader that holds the record open without delete
// sharing refuses the deletion, and refused the replacement before it), it
// expires the record (publishedSessionExpire) and writes its deny marker,
// both of which the hook checks after it read the record. Either one
// revokes, so a full volume that refuses the marker does not leave the
// allow standing. record (blocked) is the marker's content.
func revokePublishedSessionRecord(path string, record PublishedSessionRecord) error {
	err := publishedSessionRemove(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	expireErr := publishedSessionExpire(path)
	markErr := writePublishedSessionDenyMarker(path, record)
	if expireErr == nil || errors.Is(expireErr, fs.ErrNotExist) || markErr == nil {
		return nil
	}
	return errors.Join(err, expireErr, markErr)
}

// writePublishedSessionDenyMarker creates the deny marker of the record at
// path in place: no temporary file and no rename, which a reader could
// refuse. The marker denies by existing; its content only carries the
// reason, so a marker that is already there is enough.
func writePublishedSessionDenyMarker(path string, record PublishedSessionRecord) error {
	marker := publishedSessionDenyPath(path)
	parent := filepath.Dir(marker)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a folder", parent)
	}
	record.Blocked = true
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := publishedSessionCreate(marker)
	if err != nil {
		if _, statErr := os.Lstat(marker); statErr == nil {
			return nil
		}
		return err
	}
	_ = publishedSessionFileMode(file)
	_, _ = file.Write(data)
	_ = file.Close()
	return nil
}

// PublishedSessionGeneration is the current generation of the record folder
// root, which the gateway reads before the guardian's removals and stamps
// its answer with: the modification time, in nanoseconds, of the folder's
// generation file, which must be a regular file that root/SYSTEM or
// Administrators own. Anything else is an error; an answer stamped without
// a generation proves nothing.
func PublishedSessionGeneration(root string) (string, error) {
	path, ok := PublishedSessionGenerationPath(root)
	if !ok {
		return "", fmt.Errorf("no protected session record folder %q", root)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if err := publishedSessionGenerationOwner(path, info, false); err != nil {
		return "", err
	}
	return publishedSessionGenerationValue(path, info)
}

// publishedSessionGenerationValue is the generation the file at path, whose
// information is info, holds.
func publishedSessionGenerationValue(path string, info os.FileInfo) (string, error) {
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	stamp := info.ModTime().UnixNano()
	if stamp <= 0 {
		return "", fmt.Errorf("%s holds no generation", path)
	}
	return strconv.FormatInt(stamp, 10), nil
}

// readPublishedSessionGeneration reads the generation for the hook, after
// trust accepted the generation file and every folder above it
// (ValidatePublishedSessionPath, which also requires a root/SYSTEM or
// Administrators owner for it).
func readPublishedSessionGeneration(root string, trust func(string) error) (string, error) {
	path, ok := PublishedSessionGenerationPath(root)
	if !ok {
		return "", fmt.Errorf("no protected session record folder %q", root)
	}
	if err := trust(path); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	return publishedSessionGenerationValue(path, info)
}

// BumpPublishedSessionGeneration starts a new generation of the record
// folder root, so that no allow written before it proves anything during an
// outage. Only root or SYSTEM calls it: the lifecycle before it changes
// anything and again after it put the folder back closed, and the guardian
// after it recorded a removal. It moves the generation file's modification
// time past the current one, never back (metadata only: it needs no free
// space, and on Windows no reader's sharing mode refuses it). A missing
// file is created, and one that is not a regular file of this account is
// replaced. When the time does not take, the file is removed: the hook then
// finds no generation and blocks every outage allow until the next bump.
// root must be a real folder: a root that is missing may come back with its
// own old generation file, which only a bump after its return can end. The
// error reports a bump that neither moved the generation nor removed it.
func BumpPublishedSessionGeneration(root string) error {
	return BumpPublishedSessionGenerationPast(root, time.Time{})
}

// BumpPublishedSessionGenerationPast is BumpPublishedSessionGeneration with
// a floor: the new generation is also later than floor. A lifecycle that
// replaces the record folder with a new one passes the generation of the
// folder it retired, so the new folder's first generation never repeats or
// precedes one a record was ever stamped with, even after the clock was set
// back.
func BumpPublishedSessionGenerationPast(root string, floor time.Time) error {
	path, ok := PublishedSessionGenerationPath(root)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("%s is not a folder", filepath.Dir(path))
	}
	old, err := ownPublishedSessionGeneration(path)
	if err != nil {
		return err
	}
	if floor.After(old) {
		old = floor
	}
	next := time.Now()
	if !next.After(old) {
		next = old.Add(time.Microsecond)
	}
	// The second time covers a file system that keeps whole seconds.
	var setErr error
	for _, at := range []time.Time{next, old.Add(time.Second)} {
		if setErr = publishedSessionSetTime(path, at); setErr != nil {
			break
		}
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.ModTime().After(old) {
			return nil
		}
		setErr = fmt.Errorf("%s kept its modification time", path)
	}
	if err := publishedSessionRemove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(setErr, err)
	}
	return nil
}

// ownPublishedSessionGeneration returns the modification time of the
// generation file at path, which it creates when it is missing. A file that
// is not a regular file this account owns is replaced first.
func ownPublishedSessionGeneration(path string) (time.Time, error) {
	for attempt := 0; attempt < 3; attempt++ {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			if err := createPublishedSessionGeneration(path); err != nil && !errors.Is(err, fs.ErrExist) {
				return time.Time{}, err
			}
			continue
		}
		if err != nil {
			return time.Time{}, err
		}
		if info.Mode().IsRegular() && publishedSessionGenerationOwner(path, info, true) == nil {
			return info.ModTime(), nil
		}
		if err := os.RemoveAll(path); err != nil {
			return time.Time{}, err
		}
	}
	return time.Time{}, fmt.Errorf("%s keeps changing", path)
}

// CheckPublishedForeignHookSession decides a guarded call during a gateway
// outage from the protected record of identity under root. It returns the
// scan's decision when a trusted record of the agent process proves it not
// blocked, carries the current generation, no record or deny marker blocks
// it, every record it read is still in place and fresh
// (publishedSessionMaxAge, publishedSessionClockSkew), and no lifecycle
// holds the folder (PublishedSessionHeld); a denial with the
// gateway's reason when a record or marker blocks it; and
// ErrPublishedSessionUnavailable otherwise. A session record alone never
// proves an allow: an agent process the hook cannot name may be one that
// started during the outage and resumed the session ID. trust checks a
// record or generation file path and every folder above it
// (ValidatePublishedSessionPath in production).
func CheckPublishedForeignHookSession(root, identity string, key SessionKey, decision GuardDecision, trust func(path string) error) (GuardDecision, error) {
	name := strings.TrimSpace(key.Connector)
	dir, ok := PublishedSessionIdentityDir(root, identity)
	if !ok || !key.valid() || !publishedSessionConnector(name) || trust == nil {
		return decision, ErrPublishedSessionUnavailable
	}
	now := time.Now()
	proven, proof := false, ""
	type readRecord struct {
		path string
		info os.FileInfo
		at   time.Time
	}
	var read []readRecord
	for _, entry := range []struct{ kind, id string }{{sessionKindProcess, key.Process}, {sessionKindSession, key.Session}} {
		if entry.id == "" {
			continue
		}
		path := publishedSessionPath(dir, name, entry.kind, entry.id)
		record, info, exists, err := readPublishedSessionRecord(path, trust)
		if err != nil {
			return decision, fmt.Errorf("%w: %v", ErrPublishedSessionUnavailable, err)
		}
		if !exists {
			continue
		}
		if record.Version != publishedSessionVersion || record.Connector != name || record.Kind != entry.kind || record.ID != entry.id {
			return decision, fmt.Errorf("%w: %s does not belong to this agent session", ErrPublishedSessionUnavailable, path)
		}
		at, err := time.Parse(time.RFC3339, record.At)
		if err != nil {
			return decision, fmt.Errorf("%w: %s has no valid time", ErrPublishedSessionUnavailable, path)
		}
		if record.Blocked {
			return publishedBlockDecision(decision, name, record), nil
		}
		read = append(read, readRecord{path, info, at})
		// Only the process record is proof: the gateway carries a block of
		// the process to every session it runs, and an agent process is
		// never another one.
		if entry.kind == sessionKindProcess {
			proven, proof = true, record.Generation
		}
	}
	// The deny markers are checked after the records were read: a
	// revocation that could not delete or replace a record wrote its marker
	// before it returned, so a record read before that is overruled here.
	for _, entry := range []struct{ kind, id string }{{sessionKindProcess, key.Process}, {sessionKindSession, key.Session}} {
		if entry.id == "" {
			continue
		}
		path := publishedSessionPath(dir, name, entry.kind, entry.id)
		record, denied, err := readPublishedSessionDenyMarker(path, name, entry.kind, entry.id, trust)
		if err != nil {
			return decision, fmt.Errorf("%w: %v", ErrPublishedSessionUnavailable, err)
		}
		if denied {
			return publishedBlockDecision(decision, name, record), nil
		}
	}
	if !proven {
		return decision, ErrPublishedSessionUnavailable
	}
	// Every record read must still be the same file, and fresh: a
	// revocation that could not delete a record expired it before it
	// returned, so a record read before that is overruled here too.
	for _, entry := range read {
		info, err := os.Lstat(entry.path)
		if err != nil || !os.SameFile(entry.info, info) || !publishedSessionFresh(info.ModTime(), entry.at, now) ||
			!publishedSessionFresh(entry.info.ModTime(), entry.at, now) {
			return decision, fmt.Errorf("%w: %s was revoked, replaced or expired", ErrPublishedSessionUnavailable, entry.path)
		}
	}
	// Last, the generation, read after the records: a bump that completed
	// before this read overrules an allow written before it.
	generation, err := readPublishedSessionGeneration(root, trust)
	if err != nil {
		return decision, fmt.Errorf("%w: the record folder's generation: %v", ErrPublishedSessionUnavailable, err)
	}
	if proof == "" || proof != generation {
		return decision, fmt.Errorf("%w: the record is of an earlier generation of the record folder", ErrPublishedSessionUnavailable)
	}
	// Then the hold, and the generation once more: a lifecycle that could
	// not replace or close the folder leaves its hold, and one that
	// finished while this check ran bumped the generation before it removed
	// the hold, so an allow read while the folder was held never passes.
	if PublishedSessionHeld(root) {
		return decision, fmt.Errorf("%w: a DefenseClaw lifecycle run or hook guardian pass holds the record folder: it is invalidating the records, or could not finish", ErrPublishedSessionUnavailable)
	}
	if again, err := readPublishedSessionGeneration(root, trust); err != nil || again != generation {
		return decision, fmt.Errorf("%w: the record folder's generation changed while the record was checked", ErrPublishedSessionUnavailable)
	}
	return decision, nil
}

// publishedSessionFresh reports an answer the gateway gave, and a record it
// wrote, no longer than publishedSessionMaxAge ago.
func publishedSessionFresh(modified, at, now time.Time) bool {
	return publishedSessionAgeFresh(now.Sub(modified)) && publishedSessionAgeFresh(now.Sub(at))
}

// publishedSessionAgeFresh reports an age within publishedSessionMaxAge
// that is not in the future by more than publishedSessionClockSkew: an
// answer dated ahead (the clock was ahead when the gateway wrote it, and
// was set back since) would otherwise stay fresh for as much longer than
// the limit.
func publishedSessionAgeFresh(age time.Duration) bool {
	return age >= -publishedSessionClockSkew && age <= publishedSessionMaxAge
}

// readPublishedSessionDenyMarker reports whether the record at path has a
// deny marker, with the marker's record when it is a trusted record of this
// key (else an empty one, which gives the generic reason). Anything at the
// marker path denies.
func readPublishedSessionDenyMarker(path, connectorName, kind, id string, trust func(string) error) (PublishedSessionRecord, bool, error) {
	marker := publishedSessionDenyPath(path)
	if _, err := os.Lstat(marker); errors.Is(err, fs.ErrNotExist) {
		return PublishedSessionRecord{}, false, nil
	} else if err != nil {
		return PublishedSessionRecord{}, false, err
	}
	record, _, _, err := readPublishedSessionRecord(marker, trust)
	if err != nil || record.Version != publishedSessionVersion || record.Connector != connectorName || record.Kind != kind || record.ID != id {
		return PublishedSessionRecord{}, true, nil
	}
	return record, true, nil
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
// every folder above it, with the file information of the record it read.
// A missing record does not exist; anything else that cannot be checked,
// read or decoded is an error.
func readPublishedSessionRecord(path string, trust func(string) error) (PublishedSessionRecord, os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		// The folders above must be trusted for "missing" to mean missing;
		// either way the record proves nothing.
		return PublishedSessionRecord{}, nil, false, nil
	} else if err != nil {
		return PublishedSessionRecord{}, nil, true, err
	}
	// SameFile reads the Windows file ID on first use, by path: read it now,
	// while the path still names the record this information describes.
	_ = os.SameFile(info, info)
	if err := trust(path); err != nil {
		return PublishedSessionRecord{}, nil, true, err
	}
	data, exists, err := readGuardFileLimit(path, publishedSessionRecordLimit)
	if err != nil {
		return PublishedSessionRecord{}, nil, true, err
	}
	if !exists {
		return PublishedSessionRecord{}, nil, false, nil
	}
	var record PublishedSessionRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return PublishedSessionRecord{}, nil, true, fmt.Errorf("%s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PublishedSessionRecord{}, nil, true, fmt.Errorf("%s: trailing content", path)
	}
	return record, info, true, nil
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
		err := publishedSessionRename(name, path)
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

// prunePublishedSessionRecords removes records older than
// publishedSessionMaxAge or dated after now (publishedSessionAgeFresh) and,
// past publishedSessionDirLimit, the oldest ones, plus temporary files a
// crashed writer left. A pruned record reads as missing, which blocks. A
// deny marker goes only once its record is gone: while the record stays (a
// reader may hold it open), the marker keeps it from proving an allow.
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
	var markers []string
	defer func() {
		for _, marker := range markers {
			if _, err := os.Lstat(strings.TrimSuffix(marker, publishedSessionDenySuffix) + ".json"); errors.Is(err, fs.ErrNotExist) {
				_ = os.Remove(marker)
			}
		}
	}()
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if strings.HasSuffix(entry.Name(), publishedSessionDenySuffix) {
			markers = append(markers, path)
			continue
		}
		if strings.HasPrefix(entry.Name(), ".") {
			if now.Sub(info.ModTime()) > time.Hour {
				_ = os.Remove(path)
			}
			continue
		}
		if !publishedSessionAgeFresh(now.Sub(info.ModTime())) {
			// Past its age, or dated after now. A reader may hold it open;
			// then it stays expired, and its marker stays too.
			_ = publishedSessionRemove(path)
			continue
		}
		kept = append(kept, aged{path, info.ModTime()})
	}
	if len(kept) <= publishedSessionDirLimit {
		return
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].mod.Before(kept[j].mod) })
	for _, entry := range kept[:len(kept)-publishedSessionDirLimit] {
		if publishedSessionRemove(entry.path) != nil {
			_ = publishedSessionExpire(entry.path)
		}
	}
}

// ForeignHookSessionStoreDir is the gateway's private session store of one
// caller identity under its data directory: the first 20 bytes of the
// SHA-256 of the identity (canonical when it is a uid or a SID), the folder
// the gateway has kept the account's session records in since 1.0.3. No
// standard user can reach it.
func ForeignHookSessionStoreDir(dataDir, identity string) string {
	if canonical, ok := connector.CanonicalUserScopedIdentity(identity); ok {
		identity = canonical
	}
	return filepath.Join(dataDir, sessionDirName, sha256Hex([]byte(identity))[:40])
}

// foreignHookRemovalPendingDir is the folder that carries the pending mark
// of identity: its private session store.
func foreignHookRemovalPendingDir(dataDir, identity string) (string, bool) {
	dataDir = strings.TrimSpace(dataDir)
	if _, ok := connector.CanonicalUserScopedIdentity(identity); !ok || dataDir == "" || !filepath.IsAbs(dataDir) {
		return "", false
	}
	return ForeignHookSessionStoreDir(filepath.Clean(dataDir), identity), true
}

// ForeignHookRemovalPending reports whether the guardian holds identity's
// guarded calls closed (MarkForeignHookRemovalPending): it removed one of
// the account's hooks and could not record the removal in its ledger yet,
// or could not bump the generation of the protected session records after
// it. The mark is metadata of the account's private session store under the
// gateway's data directory dataDir (ForeignHookSessionStoreDir), out of
// every standard user's reach. While it is set the gateway denies every
// guarded call of the account. A store that is not a folder or cannot be
// inspected is an error, which denies the same way.
func ForeignHookRemovalPending(dataDir, identity string) (bool, error) {
	dir, ok := foreignHookRemovalPendingDir(dataDir, identity)
	if !ok {
		return false, nil
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("the foreign-hook session store %s is not a folder", dir)
	}
	return publishedSessionPendingFlag(info), nil
}

// MarkForeignHookRemovalPending holds identity's guarded calls closed
// (ForeignHookRemovalPending) until ClearForeignHookRemovalPending. The
// guardian (root or SYSTEM) calls it when its ledger did not take a
// removal, and when it could not bump the record generation after one. The
// mark needs no free space (publishedSessionSetPending), so the failure that
// refused the ledger does not refuse it. A missing store is created for it,
// owned like the data directory, so the gateway can use it once the mark is
// cleared.
func MarkForeignHookRemovalPending(dataDir, identity string) error {
	dir, ok := foreignHookRemovalPendingDir(dataDir, identity)
	if !ok {
		return errors.New("the account has no foreign-hook session store")
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := publishedSessionCreatePendingDir(filepath.Clean(strings.TrimSpace(dataDir)), dir); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("the foreign-hook session store %s is not a folder", dir)
	}
	return publishedSessionSetPending(dir, true)
}

// ClearForeignHookRemovalPending ends the hold of
// MarkForeignHookRemovalPending. The guardian calls it once its ledger names
// an account-wide removal that covers the hold and the record generation was
// bumped after that write, so no allow written before, or while the account
// was held, proves anything. An empty store (one the mark created) goes too.
func ClearForeignHookRemovalPending(dataDir, identity string) error {
	dir, ok := foreignHookRemovalPendingDir(dataDir, identity)
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
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !publishedSessionPendingFlag(info) {
		return nil
	}
	if err := publishedSessionSetPending(dir, false); err != nil {
		return err
	}
	_ = os.Remove(dir)
	return nil
}
