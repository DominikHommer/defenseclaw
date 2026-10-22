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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
	"sync"
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
// exchange the gateway also writes its answer for the agent process and for
// the session into a record the user can read but not change:
//
//   - Linux and macOS: <HookSessionDir>/<identity digest>/. The root
//     lifecycle creates HookSessionDir, owned by the service account (mode
//     0711). The gateway creates the per-user folder (mode 0700) with one
//     access-list entry that lets only that uid read it.
//   - Windows: %ProgramData%\Cisco\DefenseClaw-HookSessions\<digest>\. The
//     SYSTEM lifecycle creates the root; the gateway creates the per-user
//     folder with a protected DACL (SYSTEM and Administrators full, the
//     gateway service modify, that user read).
//
// One kill switch (1.0.4 guard loop, lead directive). Every allow record
// carries a MAC made with the record folder's key. The key is the name of
// one file next to the record folder, <folder name>.key-<64 hex>, that only
// root or SYSTEM creates (CreatePublishedSessionKey). A record whose MAC
// does not verify with the current key proves nothing. Every revocation
// removes the key first and only then does anything else:
//
//   - the gateway, before it records a block and before it publishes any
//     denial (KillPublishedSessionKey: one unlink, then the folder is
//     flushed; the gateway may remove the file but never create one);
//   - the hook guardian, before it records a removal, and it creates a new
//     key only after the ledger write;
//   - the lifecycle (install, upgrade, repair, ensure, uninstall), before it
//     changes anything, and it creates a new key only once the run
//     succeeded.
//
// A new key never brings an earlier record back: its name is random, and
// no account but root or SYSTEM can give a file that name. So no revocation
// has to find the records it ends, and no account that kept a way to move
// records or folders around (a retained Windows handle, a macOS access-list
// entry) can make an earlier allow count again.
//
// During such an outage the hook allows a call only when all of these hold,
// and blocks otherwise:
//
//   - the record folder has exactly one key file that root, SYSTEM or
//     Administrators own, and the hook's trust check accepts it and every
//     folder above it;
//   - the records of the agent process and of the session (every key part
//     the call names) say not blocked, carry a MAC that verifies with that
//     key, and are at most publishedSessionMaxAge old. A record the call
//     needs that is missing, untrusted, corrupt or dead blocks. A blocking
//     record denies with the gateway's reason, whatever its MAC;
//   - the volume of the record folder is not read-only (where no key could
//     be removed), and the key is the same at the end of the check.
//
// No removal state lives in this tree. The guardian's ledger, and an
// account's pending mark (MarkForeignHookRemovalPending) for a removal the
// guardian could not record, are in folders no standard user can reach.

const (
	// publishedSessionVersion is the record schema: 3 carries the MAC.
	publishedSessionVersion = 3
	// publishedSessionRecordLimit bounds one record.
	publishedSessionRecordLimit = 8 << 10
	// publishedSessionReasonLimit bounds the gateway reason a record keeps.
	publishedSessionReasonLimit = 2048
	// publishedSessionDirLimit bounds the records kept per account. A
	// record pruned past it reads as missing, which blocks.
	publishedSessionDirLimit = 1024
	// PublishedSessionKeyInfix follows the record folder's name in the name
	// of its key file.
	PublishedSessionKeyInfix = ".key-"
	// publishedSessionKeyBytes is the size of a key.
	publishedSessionKeyBytes = 32
	// publishedSessionMaxAge is the oldest answer the hook accepts during an
	// outage. The gateway writes the record again at every exchange, so an
	// agent in use keeps a fresh one; an outage that lasts longer blocks.
	publishedSessionMaxAge = 15 * time.Minute
	// publishedSessionClockSkew is how far after now the hook still accepts
	// a record's time. The gateway and the hook read the same clock, so this
	// only covers a small step back of it.
	publishedSessionClockSkew = time.Minute
	// publishedSessionKeyRemoveAttempts bounds how often a key file a
	// reader holds for a moment is removed again.
	publishedSessionKeyRemoveAttempts = 3
)

// publishedSessionRemoveKey removes a key file, publishedSessionCreateKeyFile
// creates one and publishedSessionList lists a folder (replaceable in
// tests, which stand in for a key file that cannot be removed or created
// and a folder that cannot be listed).
var (
	publishedSessionRemoveKey     = os.Remove
	publishedSessionCreateKeyFile = createPublishedSessionKeyFile
	publishedSessionList          = func(dir string) ([]string, error) {
		folder, err := os.Open(dir)
		if err != nil {
			return nil, err
		}
		defer func() { _ = folder.Close() }()
		return folder.Readdirnames(-1)
	}
)

// publishedSessionKeyOwner reports whether the key file at path is a
// regular file that root, SYSTEM or Administrators own
// (publishedSessionKeyOwnerCheck). An error, other than a file that is not
// a key at all, blocks.
var (
	publishedSessionKeyOwnerMu sync.RWMutex
	publishedSessionKeyOwner   = publishedSessionKeyOwnerCheck
)

// OverridePublishedSessionKeyOwnerForTest replaces the owner check of key
// files, for tests that cannot run as root or SYSTEM.
func OverridePublishedSessionKeyOwnerForTest(check func(path string) (bool, error)) (restore func()) {
	publishedSessionKeyOwnerMu.Lock()
	previous := publishedSessionKeyOwner
	publishedSessionKeyOwner = check
	publishedSessionKeyOwnerMu.Unlock()
	return func() {
		publishedSessionKeyOwnerMu.Lock()
		publishedSessionKeyOwner = previous
		publishedSessionKeyOwnerMu.Unlock()
	}
}

func publishedSessionKeyOwned(path string) (bool, error) {
	publishedSessionKeyOwnerMu.RLock()
	check := publishedSessionKeyOwner
	publishedSessionKeyOwnerMu.RUnlock()
	return check(path)
}

// publishedSessionVolumeReadOnly reports whether the volume of a path is
// mounted read-only (replaceable in tests, which cannot mount one).
var publishedSessionVolumeReadOnly = publishedSessionVolumeIsReadOnly

// ErrPublishedSessionUnavailable is a protected session record that does
// not prove the session unblocked: missing, unreadable, untrusted, corrupt,
// stale or dead (its MAC does not verify with the current key).
var ErrPublishedSessionUnavailable = errors.New("protected foreign-hook session record unavailable")

// PublishedSessionRecord is the gateway's last answer for one agent process
// ("p") or session ("s") of one connector. An allow carries the MAC
// (publishedSessionMAC) made with the key that was current when the
// gateway read its inputs.
type PublishedSessionRecord struct {
	Version   int    `json:"v"`
	Connector string `json:"connector"`
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Blocked   bool   `json:"blocked"`
	Reason    string `json:"reason,omitempty"`
	At        string `json:"at"`
	MAC       string `json:"mac,omitempty"`
}

// PublishedSessionTrust names the accounts besides root/SYSTEM and
// Administrators that may own and write the protected record: the gateway
// service uid (Linux, macOS; from the root-owned runtime descriptor) or
// service account (Windows, which a key file lets remove it). A key file is
// never the service's.
type PublishedSessionTrust struct {
	ServiceUID     int
	ServiceAccount string
}

// SessionRecordKey is the key of a record folder: the key file and the
// secret its name holds. The zero value is no key: an allow published with
// it proves nothing.
type SessionRecordKey struct {
	path   string
	secret []byte
}

// ID names the key (its file); "" for no key.
func (k SessionRecordKey) ID() string { return k.path }

// IsZero reports no key.
func (k SessionRecordKey) IsZero() bool { return len(k.secret) == 0 }

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
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// PublishedSessionKeyDir is the folder the key file of the record folder
// root is in: the folder above root (on Linux and macOS the hook socket
// folder, which only root and the gateway service can change; on Windows
// %ProgramData%\Cisco, where no standard user may rename or delete a file
// another account made).
func PublishedSessionKeyDir(root string) (string, bool) {
	dir, _, ok := publishedSessionKeyPlace(root)
	return dir, ok
}

// publishedSessionKeyPlace is the key folder of root and the prefix of its
// key file's name.
func publishedSessionKeyPlace(root string) (dir, prefix string, ok bool) {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return "", "", false
	}
	root = filepath.Clean(root)
	if root == filepath.Dir(root) {
		return "", "", false
	}
	return filepath.Dir(root), filepath.Base(root) + PublishedSessionKeyInfix, true
}

// IsPublishedSessionKeyName reports a file name that has the form of a key
// file name: <anything>.key-<64 lower-case hex>.
func IsPublishedSessionKeyName(name string) bool {
	i := strings.LastIndex(name, PublishedSessionKeyInfix)
	if i <= 0 {
		return false
	}
	_, ok := publishedSessionKeySecret(name[i+len(PublishedSessionKeyInfix):])
	return ok
}

// publishedSessionKeySecret decodes the secret of a key file name's suffix.
func publishedSessionKeySecret(suffix string) ([]byte, bool) {
	if len(suffix) != 2*publishedSessionKeyBytes || strings.ToLower(suffix) != suffix {
		return nil, false
	}
	secret, err := hex.DecodeString(suffix)
	return secret, err == nil
}

// publishedSessionKeys lists the key files of the record folder root that
// root, SYSTEM or Administrators own. A file with the key prefix that
// another account owns is not a key (on Windows a standard user may create
// one in %ProgramData%\Cisco) and is skipped; a key folder that cannot be
// listed, or a file whose owner cannot be read, is an error.
func publishedSessionKeys(root string) ([]SessionRecordKey, error) {
	dir, prefix, ok := publishedSessionKeyPlace(root)
	if !ok {
		return nil, fmt.Errorf("no protected session record folder %q", root)
	}
	names, err := publishedSessionList(dir)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var keys []SessionRecordKey
	for _, name := range names {
		if !hasPrefixFold(name, prefix) {
			continue
		}
		secret, ok := publishedSessionKeySecret(name[len(prefix):])
		if !ok {
			continue
		}
		path := filepath.Join(dir, name)
		owned, err := publishedSessionKeyOwned(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if owned {
			keys = append(keys, SessionRecordKey{path: path, secret: secret})
		}
	}
	return keys, nil
}

// ReadPublishedSessionKey is the current key of the record folder root:
// its one key file. None, more than one, or a key folder that cannot be
// read is an error; an allow published without a key proves nothing.
func ReadPublishedSessionKey(root string) (SessionRecordKey, error) {
	keys, err := publishedSessionKeys(root)
	if err != nil {
		return SessionRecordKey{}, err
	}
	switch len(keys) {
	case 1:
		return keys[0], nil
	case 0:
		return SessionRecordKey{}, fmt.Errorf("the protected session record folder %s has no key", root)
	}
	return SessionRecordKey{}, fmt.Errorf("the protected session record folder %s has %d keys", root, len(keys))
}

// readPublishedSessionKeyForHook is ReadPublishedSessionKey after trust
// accepted the key file and every folder above it
// (ValidatePublishedSessionPath, which also requires a root, SYSTEM or
// Administrators owner).
func readPublishedSessionKeyForHook(root string, trust func(string) error) (SessionRecordKey, error) {
	key, err := ReadPublishedSessionKey(root)
	if err != nil {
		return SessionRecordKey{}, err
	}
	if err := trust(key.path); err != nil {
		return SessionRecordKey{}, err
	}
	return key, nil
}

// KillPublishedSessionKey removes every key file of the record folder root,
// so that no record written before proves anything during an outage, and
// flushes the key folder. Each removal is one unlink. The gateway calls it
// before it records a block and before it publishes a denial; the guardian
// and the lifecycle through RetirePublishedSessionKey. A key folder that
// does not exist has no key. A key file that is still there is an error.
func KillPublishedSessionKey(root string) error {
	dir, _, ok := publishedSessionKeyPlace(root)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	keys, err := publishedSessionKeys(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, key := range keys {
		for attempt := 1; ; attempt++ {
			err := publishedSessionRemoveKey(key.path)
			if err == nil || errors.Is(err, fs.ErrNotExist) {
				break
			}
			if attempt == publishedSessionKeyRemoveAttempts {
				errs = append(errs, fmt.Errorf("remove the protected session record key %s: %w", key.path, err))
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if len(keys) != 0 {
		if err := publishedSessionSyncDir(dir); err != nil {
			errs = append(errs, fmt.Errorf("flush %s: %w", dir, err))
		}
	}
	return errors.Join(errs...)
}

// RetirePublishedSessionKey is KillPublishedSessionKey for root or SYSTEM.
// When a key file cannot be removed, it adds a second one next to it: the
// hook trusts no record folder with more than one key, so the earlier
// records still prove nothing. The error says which of the two took.
func RetirePublishedSessionKey(root string, trust PublishedSessionTrust) error {
	err := KillPublishedSessionKey(root)
	if err == nil {
		return nil
	}
	if _, decoyErr := createPublishedSessionKey(root, trust); decoyErr != nil {
		return fmt.Errorf("%w; no second key could be added either, so an allow written before may still pass during a gateway outage: %v", err, decoyErr)
	}
	return fmt.Errorf("%w; a second key was added, so the hook trusts neither until a later run removes both", err)
}

// CreatePublishedSessionKey starts a new key of the record folder root
// (root or SYSTEM only): it retires every key (RetirePublishedSessionKey)
// and creates a key file with a fresh random name, then flushes the key
// folder. Only an allow published after it, with removals read after it,
// proves anything. A key file that could not be removed stays next to the
// new one, which the hook refuses. The record folder must exist.
func CreatePublishedSessionKey(root string, trust PublishedSessionTrust) error {
	info, err := os.Lstat(strings.TrimSpace(root))
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("%s is not a folder", root)
	}
	if err := KillPublishedSessionKey(root); err != nil {
		// Whatever the new key is, the hook refuses a folder with two.
		_, createErr := createPublishedSessionKey(root, trust)
		return errors.Join(err, createErr)
	}
	_, err = createPublishedSessionKey(root, trust)
	return err
}

// EnsurePublishedSessionKey gives the record folder root a key when it has
// none, or more than one (CreatePublishedSessionKey). The hook guardian
// runs it at every pass, so outage allows work again after a gateway
// removed the key. A new key never makes an earlier record count, so this
// is safe at any time. A record folder that does not exist gets none.
func EnsurePublishedSessionKey(root string, trust PublishedSessionTrust) error {
	info, err := os.Lstat(strings.TrimSpace(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil
	}
	if keys, err := publishedSessionKeys(root); err == nil && len(keys) == 1 {
		return nil
	}
	return CreatePublishedSessionKey(root, trust)
}

// createPublishedSessionKey creates one key file of root with a fresh
// random name (createPublishedSessionKeyFile: the name appears at once, in
// one create that fails when it exists) and flushes the key folder.
func createPublishedSessionKey(root string, trust PublishedSessionTrust) (string, error) {
	dir, prefix, ok := publishedSessionKeyPlace(root)
	if !ok {
		return "", fmt.Errorf("no protected session record folder %q", root)
	}
	var secret [publishedSessionKeyBytes]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	path := filepath.Join(dir, prefix+hex.EncodeToString(secret[:]))
	if err := publishedSessionCreateKeyFile(path, trust); err != nil {
		return "", fmt.Errorf("create the protected session record key %s: %w", path, err)
	}
	if err := publishedSessionSyncDir(dir); err != nil {
		return path, fmt.Errorf("flush %s: %w", dir, err)
	}
	return path, nil
}

// RemovePublishedSessionKeys removes every key file of the record folder
// root and every file with its key prefix that this account may remove:
// for uninstall, which removes the folder.
func RemovePublishedSessionKeys(root string) error {
	if err := KillPublishedSessionKey(root); err != nil {
		return err
	}
	dir, prefix, _ := publishedSessionKeyPlace(root)
	names, err := publishedSessionList(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, name := range names {
		if hasPrefixFold(name, prefix) && IsPublishedSessionKeyName(name) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	return nil
}

// publishedSessionMAC is the MAC of record for the account identity
// (canonical) with secret: HMAC-SHA256 over every field, each with its
// length.
func publishedSessionMAC(secret []byte, identity string, record PublishedSessionRecord) string {
	mac := hmac.New(sha256.New, secret)
	for _, field := range []string{
		"defenseclaw protected foreign-hook session record", strconv.Itoa(record.Version), identity,
		record.Connector, record.Kind, record.ID, strconv.FormatBool(record.Blocked), record.Reason, record.At,
	} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(field))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// publishedSessionMACValid reports a record whose MAC verifies with key.
func publishedSessionMACValid(key SessionRecordKey, identity string, record PublishedSessionRecord) bool {
	if key.IsZero() || record.MAC == "" {
		return false
	}
	want := publishedSessionMAC(key.secret, identity, record)
	return hmac.Equal([]byte(want), []byte(record.MAC))
}

// PublishForeignHookSessionDecision writes the gateway's answer for one
// session exchange into the protected records of identity under root: a
// denial records the agent process and the session as blocked, an allow
// records them as not blocked, with a MAC made with recordKey, the key the
// gateway read before it read the guardian's removals
// (ReadPublishedSessionKey). An allow without a key proves nothing. A
// denial needs no MAC: the gateway removed the key before it (an earlier
// allow is dead), and a blocking record denies whatever its MAC. root
// missing is not an error: the hook then finds no record and blocks during
// an outage.
func PublishForeignHookSessionDecision(root, identity string, key SessionKey, decision GuardDecision, recordKey SessionRecordKey, now time.Time) error {
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
	if err := publishedSessionPrepare(root, dir, canonical); err != nil {
		// A folder that is not ours is not written to.
		return err
	}
	if now.IsZero() {
		now = time.Now()
	}
	var errs []error
	created := false
	for _, entry := range publishedSessionAnswer(dir, canonical, name, key, decision, recordKey, now) {
		if _, err := os.Lstat(entry.path); errors.Is(err, fs.ErrNotExist) {
			created = true
		}
		if err := writePublishedSessionRecord(entry.path, entry.record); err != nil {
			errs = append(errs, err)
		}
	}
	if created {
		prunePublishedSessionRecords(dir, now)
	}
	return errors.Join(errs...)
}

// publishedSessionEntry is one record of an answer and where it goes.
type publishedSessionEntry struct {
	path   string
	record PublishedSessionRecord
}

// publishedSessionAnswer is the records of one answer of the gateway for
// key in the account folder dir of the account canonical: a denial blocks,
// with no MAC, and an allow carries the MAC made with recordKey (none
// without a key).
func publishedSessionAnswer(dir, canonical, name string, key SessionKey, decision GuardDecision, recordKey SessionRecordKey, now time.Time) []publishedSessionEntry {
	record := PublishedSessionRecord{
		Version:   publishedSessionVersion,
		Connector: name,
		Blocked:   decision.Deny,
		At:        now.UTC().Format(time.RFC3339),
	}
	if decision.Deny {
		record.Reason = clipPublishedReason(decision.Reason)
	}
	var entries []publishedSessionEntry
	for _, entry := range []struct{ kind, id string }{{sessionKindProcess, key.Process}, {sessionKindSession, key.Session}} {
		if entry.id == "" {
			continue
		}
		record.Kind, record.ID, record.MAC = entry.kind, entry.id, ""
		if !decision.Deny && !recordKey.IsZero() {
			record.MAC = publishedSessionMAC(recordKey.secret, canonical, record)
		}
		entries = append(entries, publishedSessionEntry{publishedSessionPath(dir, name, entry.kind, entry.id), record})
	}
	return entries
}

// WritePublishedSessionRecordsForTest writes the records the gateway
// publishes for one answer, with the record folder's current key (none when
// it has none), into an account folder it creates without the gateway's
// access list: for tests in other packages, which cannot run as the gateway
// service or give an access-list entry.
func WritePublishedSessionRecordsForTest(root, identity string, key SessionKey, decision GuardDecision, now time.Time) error {
	dir, ok := PublishedSessionIdentityDir(root, identity)
	name := strings.TrimSpace(key.Connector)
	if !ok || !key.valid() || !publishedSessionConnector(name) {
		return errors.New("invalid account or session key")
	}
	canonical, _ := connector.CanonicalUserScopedIdentity(identity)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	recordKey, _ := ReadPublishedSessionKey(root)
	var errs []error
	for _, entry := range publishedSessionAnswer(dir, canonical, name, key, decision, recordKey, now) {
		errs = append(errs, writePublishedSessionRecord(entry.path, entry.record))
	}
	return errors.Join(errs...)
}

// CheckPublishedForeignHookSession decides a guarded call during a gateway
// outage from the protected records of identity under root. It returns the
// scan's decision when the records of the agent process and of the session
// (each the call names) are trusted, not blocked, fresh, and carry a MAC
// that verifies with the record folder's one key, and the volume is not
// read-only; a denial with the gateway's reason when a record blocks it;
// and ErrPublishedSessionUnavailable otherwise. An agent process the hook
// cannot name is never proven: it may be one that started during the
// outage and resumed the session ID. trust checks a record or key file path
// and every folder above it (ValidatePublishedSessionPath in production).
func CheckPublishedForeignHookSession(root, identity string, key SessionKey, decision GuardDecision, trust func(path string) error) (GuardDecision, error) {
	name := strings.TrimSpace(key.Connector)
	dir, ok := PublishedSessionIdentityDir(root, identity)
	canonical, _ := connector.CanonicalUserScopedIdentity(identity)
	if !ok || !key.valid() || !publishedSessionConnector(name) || trust == nil {
		return decision, ErrPublishedSessionUnavailable
	}
	// The key first: a record read after it was written under it or under
	// an earlier one.
	recordKey, err := readPublishedSessionKeyForHook(root, trust)
	if err != nil {
		return decision, fmt.Errorf("%w: the record folder's key: %v", ErrPublishedSessionUnavailable, err)
	}
	now := time.Now()
	var allows []PublishedSessionRecord
	missing := key.Process == ""
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
			missing = true
			continue
		}
		if record.Version != publishedSessionVersion || record.Connector != name || record.Kind != entry.kind || record.ID != entry.id {
			return decision, fmt.Errorf("%w: %s does not belong to this agent session", ErrPublishedSessionUnavailable, path)
		}
		if record.Blocked {
			return publishedBlockDecision(decision, name, record), nil
		}
		allows = append(allows, record)
	}
	if missing {
		return decision, fmt.Errorf("%w: no record proves this agent process and session", ErrPublishedSessionUnavailable)
	}
	for _, record := range allows {
		at, err := time.Parse(time.RFC3339, record.At)
		if err != nil || !publishedSessionAgeFresh(now.Sub(at)) {
			return decision, fmt.Errorf("%w: the %s record is stale or has no valid time", ErrPublishedSessionUnavailable, record.Kind)
		}
		if !publishedSessionMACValid(recordKey, canonical, record) {
			return decision, fmt.Errorf("%w: the %s record was not written under the record folder's current key", ErrPublishedSessionUnavailable, record.Kind)
		}
	}
	// A record folder on a volume that is read-only proves nothing: no key
	// could be removed there.
	if readOnly, err := publishedSessionVolumeReadOnly(root); err != nil || readOnly {
		return decision, fmt.Errorf("%w: the record folder's volume is read-only, or its state cannot be read: %v", ErrPublishedSessionUnavailable, err)
	}
	// Last, the key again: one removed while this check ran ends the allow.
	if again, err := readPublishedSessionKeyForHook(root, trust); err != nil || again.ID() != recordKey.ID() {
		return decision, fmt.Errorf("%w: the record folder's key changed while the record was checked", ErrPublishedSessionUnavailable)
	}
	return decision, nil
}

// publishedSessionAgeFresh reports an age within publishedSessionMaxAge
// that is not in the future by more than publishedSessionClockSkew: an
// answer dated ahead (the clock was ahead when the gateway wrote it, and
// was set back since) would otherwise stay fresh for as much longer than
// the limit.
func publishedSessionAgeFresh(age time.Duration) bool {
	return age >= -publishedSessionClockSkew && age <= publishedSessionMaxAge
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

// prunePublishedSessionRecords removes records older than
// publishedSessionMaxAge or dated after now (publishedSessionAgeFresh) and,
// past publishedSessionDirLimit, the oldest ones, plus temporary files a
// crashed writer left. A pruned record reads as missing, which blocks.
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
		if !publishedSessionAgeFresh(now.Sub(info.ModTime())) {
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

// hasPrefixFold reports whether name starts with prefix, ignoring case (the
// Windows file system does).
func hasPrefixFold(name, prefix string) bool {
	return len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix)
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
// or could not remove the record key before it. The mark is metadata of
// the account's private session store under the gateway's data directory
// dataDir (ForeignHookSessionStoreDir), out of every standard user's reach.
// While it is set the gateway denies every guarded call of the account. A
// store that is not a folder or cannot be inspected is an error, which
// denies the same way.
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
// removal, and when it could not remove the record key before one. The
// mark needs no free space (publishedSessionSetPending), so the failure
// that refused the ledger does not refuse it. A missing store is created
// for it, owned like the data directory, so the gateway can use it once
// the mark is cleared.
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
// an account-wide removal that covers the hold, written after it removed
// the record key, so no allow written before, or while the account was
// held, proves anything. An empty store (one the mark created) goes too.
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
