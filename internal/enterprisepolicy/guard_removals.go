// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
)

// Foreign-hook removals.
//
// An agent keeps the hooks its process loaded at start, and some agents send
// their session-start event only with the first prompt (Hermes), so the
// session-start snapshot can miss a hook the guardian removed in between.
// The guardian therefore records each removal (account, connector, file and
// time) in its protected authorization directory, and the gateway denies the
// calls of that account's agent processes of that connector (and of any
// other that loads the file) that started before the removal: they may
// still run the hook. A process that started afterwards loaded the cleaned
// files, and other accounts and connectors are not affected. A process
// DefenseClaw cannot name has no start time to compare, so only its
// session-start snapshot applies.

// ForeignHookRemovalsFile is the removal ledger in the hook guardian's
// authorization directory. The guardian writes it; the gateway reads it.
const ForeignHookRemovalsFile = "foreign-hook-removals.json"

// ForeignHookCleanupPendingPrefix starts the path of a pending cleanup
// denial: an account/connector cleanup whose file edits have not yet been
// committed to the removal ledger. The gateway denies that connector while
// it is present, including processes with no provable start time. The path
// is ForeignHookCleanupPendingPath(id, owner): a unique id lets concurrent
// cleanups coexist, and owner names the guardian process that runs the
// cleanup, so that a later pass can tell an abandoned denial from a live one.
const ForeignHookCleanupPendingPrefix = "<foreign-hook cleanup pending:"

// ForeignHookCleanupIncompletePath is the path of the removal a cleanup
// records when it ended without telling exactly which files it changed (a
// failed worker, an edit error, an abandoned cleanup): every agent process
// of the account and connector that started before it may still run a hook
// that cleanup removed, so it is denied until it restarts, like after any
// removal. Agents started later loaded the files as they are now.
const ForeignHookCleanupIncompletePath = "<foreign-hook cleanup incomplete>"

const (
	foreignHookRemovalsVersion = 1
	// foreignHookRemovalsLimit bounds the removal entries and
	// foreignHookRemovalsBytes what they take; the newest are kept.
	foreignHookRemovalsLimit = 1024
	foreignHookRemovalsBytes = 1 << 20
	// foreignHookCleanupLimit and foreignHookCleanupBytes bound the entries
	// cleanup transactions leave (foreignHookCleanupEntry). They have their
	// own budget, so a cleanup never pushes a removal out of the ledger,
	// also one that removed nothing: a cleanup whose pending denial does not
	// fit is refused before it edits anything, and one whose end does not
	// fit keeps its pending denial.
	foreignHookCleanupLimit = 4096
	foreignHookCleanupBytes = 1 << 20
	// ForeignHookRemovalsMaxBytes bounds the ledger file.
	ForeignHookRemovalsMaxBytes = foreignHookRemovalsBytes + foreignHookCleanupBytes
)

// ForeignHookCleanupPending reports whether path is a pending cleanup
// denial.
func ForeignHookCleanupPending(path string) bool {
	return strings.HasPrefix(path, ForeignHookCleanupPendingPrefix)
}

// foreignHookCleanupEntry reports whether path is an entry a cleanup
// transaction leaves: a pending denial or an incomplete cleanup's removal.
func foreignHookCleanupEntry(path string) bool {
	return ForeignHookCleanupPending(path) || path == ForeignHookCleanupIncompletePath
}

// ForeignHookCleanupPendingPath is the path of the pending denial of
// cleanup id, run by the process whose agentprocess identity is owner ("" if
// it cannot be named).
func ForeignHookCleanupPendingPath(id, owner string) string {
	return ForeignHookCleanupPendingPrefix + id + ":" + owner + ">"
}

// ForeignHookCleanupPendingOwner returns the owner a pending denial path
// names, or "".
func ForeignHookCleanupPendingOwner(path string) string {
	rest, ok := strings.CutPrefix(path, ForeignHookCleanupPendingPrefix)
	if !ok {
		return ""
	}
	rest, ok = strings.CutSuffix(rest, ">")
	if !ok {
		return ""
	}
	_, owner, _ := strings.Cut(rest, ":")
	return owner
}

// ForeignHookRemoval is one hook file the guardian cleaned for an account.
type ForeignHookRemoval struct {
	// Identity is the account as the gateway names a verified caller: a
	// decimal uid or an upper-case SID.
	Identity  string `json:"identity"`
	Connector string `json:"connector"`
	Path      string `json:"path"`
	// At is when the removal was recorded, after the file was cleaned, and
	// Mark is the same instant as an agent process start time
	// (agentprocess.Now).
	At   string `json:"at"`
	Mark string `json:"mark"`
}

type foreignHookRemovalLedger struct {
	Version  int                  `json:"version"`
	Removals []ForeignHookRemoval `json:"removals"`
}

// ParseForeignHookRemovals decodes the ledger. Anything but a complete
// version 1 ledger is an error.
func ParseForeignHookRemovals(data []byte) ([]ForeignHookRemoval, error) {
	if len(data) > ForeignHookRemovalsMaxBytes {
		return nil, errors.New("foreign-hook removal ledger exceeds the size limit")
	}
	var ledger foreignHookRemovalLedger
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil {
		return nil, fmt.Errorf("parse foreign-hook removal ledger: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse foreign-hook removal ledger: trailing content")
	}
	if ledger.Version != foreignHookRemovalsVersion {
		return nil, errors.New("foreign-hook removal ledger has an invalid schema")
	}
	removals, cleanups := 0, 0
	for _, removal := range ledger.Removals {
		if _, err := time.Parse(time.RFC3339Nano, removal.At); err != nil || !removal.complete() {
			return nil, errors.New("foreign-hook removal ledger contains an incomplete entry")
		}
		if foreignHookCleanupEntry(removal.Path) {
			cleanups++
		} else {
			removals++
		}
	}
	if removals > foreignHookRemovalsLimit || cleanups > foreignHookCleanupLimit {
		return nil, errors.New("foreign-hook removal ledger has an invalid schema")
	}
	return ledger.Removals, nil
}

func (r ForeignHookRemoval) complete() bool {
	return r.Identity != "" && r.Connector != "" && r.Path != "" && r.Mark != ""
}

// foreignHookRemovalIndent bounds what indentation adds to one encoded
// entry, and to the ledger around them.
const foreignHookRemovalIndent = 64

// EncodeForeignHookRemovals adds added to existing, keeping the latest entry
// per account, connector and file, drops incomplete entries and removals
// older than sessionRecordTTL (a session block lasts as long), keeps the
// newest removals that fit foreignHookRemovalsLimit and
// foreignHookRemovalsBytes, and encodes the ledger. The entries cleanup
// transactions leave have their own budget, so they never displace a
// removal: when they do not all fit, encoding fails. Pending denials never
// expire here; the guardian settles them. The gateway denies every
// account's calls while the ledger does not parse, so one account's removals
// (paths the user names) must never make it unreadable.
func EncodeForeignHookRemovals(existing, added []ForeignHookRemoval, now time.Time) ([]byte, error) {
	type dated struct {
		removal ForeignHookRemoval
		at      time.Time
		key     string
	}
	latest := map[string]dated{}
	for _, removal := range append(append([]ForeignHookRemoval{}, existing...), added...) {
		at, err := time.Parse(time.RFC3339Nano, removal.At)
		if err != nil || now.Sub(at) > sessionRecordTTL && !ForeignHookCleanupPending(removal.Path) || !removal.complete() {
			continue
		}
		key := removal.Identity + "\x00" + removal.Connector + "\x00" + removal.Path
		if previous, ok := latest[key]; !ok || !at.Before(previous.at) {
			latest[key] = dated{removal, at, key}
		}
	}
	entries := make([]dated, 0, len(latest))
	for _, entry := range latest {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		pi := foreignHookCleanupEntry(entries[i].removal.Path)
		pj := foreignHookCleanupEntry(entries[j].removal.Path)
		if pi != pj {
			return pi
		}
		if !entries[i].at.Equal(entries[j].at) {
			return entries[i].at.After(entries[j].at)
		}
		return entries[i].key < entries[j].key
	})
	ledger := foreignHookRemovalLedger{Version: foreignHookRemovalsVersion, Removals: []ForeignHookRemoval{}}
	removals, removalsSize, removalsFull := 0, foreignHookRemovalIndent, false
	cleanups, cleanupsSize := 0, 0
	for _, entry := range entries {
		encoded, err := json.Marshal(entry.removal)
		if err != nil {
			return nil, err
		}
		cost := len(encoded) + foreignHookRemovalIndent
		if foreignHookCleanupEntry(entry.removal.Path) {
			if cleanups == foreignHookCleanupLimit || cleanupsSize+cost > foreignHookCleanupBytes {
				return nil, errors.New("foreign-hook removal ledger cannot retain every cleanup denial")
			}
			cleanups, cleanupsSize = cleanups+1, cleanupsSize+cost
		} else {
			if removalsFull || removals == foreignHookRemovalsLimit || removalsSize+cost > foreignHookRemovalsBytes {
				removalsFull = true
				continue
			}
			removals, removalsSize = removals+1, removalsSize+cost
		}
		ledger.Removals = append(ledger.Removals, entry.removal)
	}
	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return nil, err
	}
	if data = append(data, '\n'); len(data) > ForeignHookRemovalsMaxBytes {
		return nil, errors.New("foreign-hook removal ledger exceeds the size limit")
	}
	return data, nil
}

// ForeignHookRemovalConnectors returns connector and each of candidates
// whose agent loads the user file path from its default location under
// home: Cursor and Devin also load Claude Code's ~/.claude/settings.json. A
// pass removes an entry once, for the first connector it cleans, so the
// removal is recorded for every agent that may have loaded it.
func ForeignHookRemovalConnectors(home, path, connector string, candidates []string) []string {
	out := []string{connector}
	for _, name := range candidates {
		if slices.Contains(out, name) {
			continue
		}
		for _, source := range guardSources(GuardRequest{Connector: name, Home: home, AccountHome: home}) {
			if source.scope == ScopeUser && samePath(filepath.Clean(source.path), filepath.Clean(path)) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// removalAfterProcessStart returns the earliest live removal of the key's
// connector that the guardian recorded after the key's agent process
// started.
func removalAfterProcessStart(removals []ForeignHookRemoval, key SessionKey, now time.Time) (ForeignHookRemoval, bool) {
	var found ForeignHookRemoval
	var foundAt time.Time
	for _, removal := range removals {
		if !strings.EqualFold(removal.Connector, key.Connector) ||
			!ForeignHookCleanupPending(removal.Path) && !agentprocess.StartedBefore(key.Process, removal.Mark) {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, removal.At)
		if err != nil || now.Sub(at) > sessionRecordTTL && !ForeignHookCleanupPending(removal.Path) {
			continue
		}
		if foundAt.IsZero() || at.Before(foundAt) {
			found, foundAt = removal, at
		}
	}
	return found, !foundAt.IsZero()
}

// sessionRemovedNote ends a denial for an agent process that started before
// the guardian removed a hook.
const sessionRemovedNote = "The agent can keep running a hook it loaded when it started, even after the file changes, so DefenseClaw blocks this agent's tool calls until it restarts: restart the agent."

// removedSessionReason is the reason of a block for an agent process that
// started before the guardian removed one of its connector's hooks.
const removedSessionReason = "removed after this agent process started"

// removedHookDecision denies a call of an agent process that started before
// the guardian removed an unapproved hook of its connector for this account.
func removedHookDecision(decision GuardDecision, connector string, removal ForeignHookRemoval) GuardDecision {
	decision.Deny = true
	if ForeignHookCleanupPending(removal.Path) {
		decision.Reason = "enterprise_foreign_hook_blocked: DefenseClaw is removing unapproved " + connector +
			" hooks; the cleanup and its denial record are not complete. Retry the tool call after the guardian finishes."
		return decision
	}
	removed := "removed an unapproved hook from " + removal.Path
	if removal.Path == ForeignHookCleanupIncompletePath {
		removed = "ran a cleanup of unapproved hooks that did not finish, which may have removed a hook this agent loaded,"
	}
	decision.Reason = fmt.Sprintf(
		"enterprise_foreign_hook_blocked: your organization blocks %s hooks it has not approved, because they can change a tool call after DefenseClaw checks it. This agent started before DefenseClaw %s at %s. %s",
		connector, removed, removal.At, sessionRemovedNote,
	)
	decision.Findings = append([]Finding{{
		Connector: connector,
		Path:      removal.Path,
		Reason:    removedSessionReason,
	}}, decision.Findings...)
	return decision
}
