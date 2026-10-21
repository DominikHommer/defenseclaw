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
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The holds of the protected session records (GAP-0352, 1.0.4 review loop
// rounds 4 and 5).
//
// A hold is a file whose name starts with <name of the record folder>.hold
// (managed.HookSessionHoldPrefix) in the hold folder of the record folder
// (PublishedSessionHoldDir). While any hold is there, or the hold folder
// cannot be listed, the hook allows nothing during an outage. The hold
// folder is one that no standard user can add a file to:
//
//   - Linux and macOS: the folder above the record folder, which only root
//     and the gateway service can change;
//   - Windows: the hook runtime folder
//     (%ProgramData%\Cisco\DefenseClaw-HookRuntime), which only SYSTEM and
//     Administrators can change: the hook refuses the machine policy summary
//     in it, and so blocks every guarded call, when anyone else can. Not the
//     Cisco folder above the record folder: a stock ProgramData access list
//     lets standard users create files there, so an account could put its
//     own file at the hold path before a lifecycle run and delete it once
//     the run failed (1.0.4 review loop round 5).
//
// There are two kinds of hold:
//
//   - The lifecycle's (<name>.hold, HoldPublishedSessionRecords). A run that
//     cannot replace or close the record folder for certain cannot rely on
//     anything it writes into that folder to end the allows in it: an
//     account that kept a way to change the folder (a Windows handle with
//     WRITE_DAC that refuses the move, a macOS access-list entry the run
//     could not take away) may put an older generation file and its allows
//     back once the run stops. So the run holds the records before it
//     changes the folder and releases them only after the folder was
//     replaced or closed and its generation bumped; a failed run leaves the
//     hold until a later run succeeds.
//   - The guardian's, one per account (<name>.hold-removal-<digest>,
//     HoldPublishedSessionRemoval). The guardian puts it in place before it
//     publishes a removal and releases it only after a generation bump that
//     followed the removal succeeded. A pass that stops, or cannot bump, in
//     between leaves it: the gateway already denies from the new removal
//     ledger, so an allow of the generation the bump would have ended must
//     not prove anything during an outage either (1.0.4 review loop round
//     5).
//
// A file already at a hold path that DefenseClaw did not make (not a
// regular file of this account, or one another account may change or
// delete) is replaced before the run or pass changes anything.

// publishedSessionRemovalHoldInfix follows managed.HookSessionHoldPrefix in
// the name of a guardian's hold.
const publishedSessionRemovalHoldInfix = "-removal-"

// publishedSessionRemovalHoldAccount starts the line of a guardian's hold
// that names its account.
const publishedSessionRemovalHoldAccount = "account "

// publishedSessionHoldReadLimit bounds the read of a guardian's hold.
const publishedSessionHoldReadLimit = 4 << 10

// publishedSessionHoldList lists the hold folder (replaceable in tests,
// which stand in for a lifecycle that finishes while the hook checks, and
// for a folder that cannot be listed).
var publishedSessionHoldList = func(dir string) ([]string, error) {
	folder, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = folder.Close() }()
	return folder.Readdirnames(-1)
}

// publishedSessionHoldPlace is the hold folder of the record folder root and
// the prefix of its holds' names.
func publishedSessionHoldPlace(root string) (dir, prefix string, ok bool) {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return "", "", false
	}
	root = filepath.Clean(root)
	if root == filepath.Dir(root) {
		return "", "", false
	}
	return publishedSessionHoldDir(root), managed.HookSessionHoldPrefix(root), true
}

// PublishedSessionHoldDir is the folder the holds of the record folder root
// are in.
func PublishedSessionHoldDir(root string) (string, bool) {
	dir, _, ok := publishedSessionHoldPlace(root)
	return dir, ok
}

// PublishedSessionHoldPath is the lifecycle's hold of the record folder
// root.
func PublishedSessionHoldPath(root string) (string, bool) {
	dir, prefix, ok := publishedSessionHoldPlace(root)
	if !ok {
		return "", false
	}
	return filepath.Join(dir, prefix), true
}

// PublishedSessionRemovalHoldPath is the guardian's hold of the record
// folder root for the account identity (a decimal uid or a SID).
func PublishedSessionRemovalHoldPath(root, identity string) (string, bool) {
	canonical, ok := connector.CanonicalUserScopedIdentity(identity)
	dir, prefix, placed := publishedSessionHoldPlace(root)
	if !ok || !placed {
		return "", false
	}
	return filepath.Join(dir, prefix+publishedSessionRemovalHoldInfix+sha256Hex([]byte(canonical))[:40]), true
}

// HoldPublishedSessionRecords puts the lifecycle's hold of the record folder
// root in place: from now on the hook allows nothing during an outage,
// until ReleasePublishedSessionRecords. The hold folder must exist.
func HoldPublishedSessionRecords(root string) error {
	path, ok := PublishedSessionHoldPath(root)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	return holdPublishedSessionAt(path, publishedSessionHoldText)
}

// ReleasePublishedSessionRecords removes the lifecycle's hold of the record
// folder root, once the folder was replaced or closed and its generation
// bumped. The guardian's holds stay.
func ReleasePublishedSessionRecords(root string) error {
	path, ok := PublishedSessionHoldPath(root)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	return releasePublishedSessionAt(path)
}

// HoldPublishedSessionRemoval puts the guardian's hold of the record folder
// root for the account identity in place, before the guardian publishes a
// removal of that account: from now on the hook allows nothing during an
// outage, until ReleasePublishedSessionRemoval. The hold names the account,
// so that a later pass for another account can close it in the gateway and
// end the hold (PublishedSessionRemovalHolds).
func HoldPublishedSessionRemoval(root, identity string) error {
	path, ok := PublishedSessionRemovalHoldPath(root, identity)
	if !ok {
		return fmt.Errorf("no protected session record folder %q or account %q", root, identity)
	}
	canonical, _ := connector.CanonicalUserScopedIdentity(identity)
	return holdPublishedSessionAt(path, publishedSessionHoldText+publishedSessionRemovalHoldAccount+canonical+"\n")
}

// ReleasePublishedSessionRemoval removes the guardian's hold of the record
// folder root for the account identity, once a generation bump after the
// account's removal succeeded.
func ReleasePublishedSessionRemoval(root, identity string) error {
	path, ok := PublishedSessionRemovalHoldPath(root, identity)
	if !ok {
		return fmt.Errorf("no protected session record folder %q or account %q", root, identity)
	}
	return releasePublishedSessionAt(path)
}

// PublishedSessionRemovalHold is a guardian's hold in place: its path and
// the account it names, or "" when the hold is not one the guardian made
// for that account (it then stays: no pass can tell whose removal it
// covers).
type PublishedSessionRemovalHold struct {
	Path     string
	Identity string
}

// PublishedSessionRemovalHolds lists the guardian's holds of the record
// folder root.
func PublishedSessionRemovalHolds(root string) ([]PublishedSessionRemovalHold, error) {
	_, prefix, _ := publishedSessionHoldPlace(root)
	paths, err := PublishedSessionHolds(root)
	if err != nil {
		return nil, err
	}
	var holds []PublishedSessionRemovalHold
	for _, path := range paths {
		if !hasPrefixFold(filepath.Base(path), prefix+publishedSessionRemovalHoldInfix) {
			continue
		}
		identity := publishedSessionRemovalHoldIdentity(path)
		if want, ok := PublishedSessionRemovalHoldPath(root, identity); !ok || filepath.Base(want) != filepath.Base(path) {
			identity = ""
		}
		holds = append(holds, PublishedSessionRemovalHold{Path: path, Identity: identity})
	}
	return holds, nil
}

// publishedSessionRemovalHoldIdentity is the account a trusted guardian's
// hold at path names, or "".
func publishedSessionRemovalHoldIdentity(path string) string {
	if !publishedSessionHoldTrusted(path) {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	identity := ""
	lines := bufio.NewScanner(io.LimitReader(file, publishedSessionHoldReadLimit))
	for lines.Scan() {
		if rest, ok := strings.CutPrefix(lines.Text(), publishedSessionRemovalHoldAccount); ok {
			identity = strings.TrimSpace(rest)
		}
	}
	if lines.Err() != nil {
		return ""
	}
	canonical, ok := connector.CanonicalUserScopedIdentity(identity)
	if !ok {
		return ""
	}
	return canonical
}

// PublishedSessionHolds lists every hold of the record folder root in
// place, the lifecycle's and the guardian's. A missing hold folder holds
// nothing: on Windows the hook then finds no machine policy summary, and on
// Linux and macOS no record folder, so neither proves an allow. A folder
// that cannot be listed is an error.
func PublishedSessionHolds(root string) ([]string, error) {
	dir, prefix, ok := publishedSessionHoldPlace(root)
	if !ok {
		return nil, fmt.Errorf("no protected session record folder %q", root)
	}
	names, err := publishedSessionHoldList(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var holds []string
	for _, name := range names {
		if hasPrefixFold(name, prefix) {
			holds = append(holds, filepath.Join(dir, name))
		}
	}
	return holds, nil
}

// RemovePublishedSessionHolds removes every hold of the record folder root,
// the guardian's too: for uninstall, which removes the folder.
func RemovePublishedSessionHolds(root string) error {
	holds, err := PublishedSessionHolds(root)
	if err != nil {
		return err
	}
	var errs []error
	for _, path := range holds {
		errs = append(errs, releasePublishedSessionAt(path))
	}
	return errors.Join(errs...)
}

// PublishedSessionHeld reports whether the record folder root is held: any
// hold is in place, or the hold folder cannot be listed.
func PublishedSessionHeld(root string) bool {
	holds, err := PublishedSessionHolds(root)
	return err != nil || len(holds) != 0
}

// holdPublishedSessionAt makes path a hold with text. A hold DefenseClaw
// made (publishedSessionHoldTrusted) stays; anything else at the path is
// replaced, so no account keeps a way to delete the hold.
func holdPublishedSessionAt(path, text string) error {
	for attempt := 0; attempt < 3; attempt++ {
		_, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			if err := createPublishedSessionHold(path, text); err != nil {
				if errors.Is(err, fs.ErrExist) {
					continue
				}
				return err
			}
			return nil
		}
		if err != nil {
			return err
		}
		if publishedSessionHoldTrusted(path) {
			return nil
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("replace %s, which is not a hold DefenseClaw made: %w", path, err)
		}
	}
	return fmt.Errorf("%s keeps changing", path)
}

// releasePublishedSessionAt removes the hold at path.
func releasePublishedSessionAt(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s is still there", path)
	}
	return nil
}

// hasPrefixFold reports whether name starts with prefix, ignoring case (the
// Windows file system does).
func hasPrefixFold(name, prefix string) bool {
	return len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix)
}

// publishedSessionHoldText only explains the hold file: an empty one holds
// just the same.
const publishedSessionHoldText = "A DefenseClaw lifecycle run or hook guardian pass is invalidating the protected foreign-hook session records, " +
	"or could not finish doing so. While this file exists, guarded connectors block during a gateway outage. Run the DefenseClaw repair.\n"

// publishedSessionGenerationFloorLimit bounds how far ahead of the clock
// the generation of a replaced record folder is carried: further ahead it
// can only be a time someone set, and carrying it could run the generation
// past what a nanosecond count holds.
const publishedSessionGenerationFloorLimit = 24 * time.Hour

// PublishedSessionGenerationFloor is the generation of the record folder
// root that a lifecycle is about to replace, for
// BumpPublishedSessionGenerationPast on the new folder: the zero time when
// the gateway would not trust its generation file, or when it is more than
// publishedSessionGenerationFloorLimit ahead of the clock.
func PublishedSessionGenerationFloor(root string) time.Time {
	generation, err := PublishedSessionGeneration(root)
	if err != nil {
		return time.Time{}
	}
	stamp, err := strconv.ParseInt(generation, 10, 64)
	if err != nil {
		return time.Time{}
	}
	at := time.Unix(0, stamp)
	if at.After(time.Now().Add(publishedSessionGenerationFloorLimit)) {
		return time.Time{}
	}
	return at
}
