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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The hold of the protected session records (GAP-0352, 1.0.4 review loop
// round 4).
//
// A lifecycle that cannot replace or close the record folder for certain
// cannot rely on anything it writes into that folder to end the allows in
// it: an account that kept a way to change the folder (a Windows handle
// with WRITE_DAC that refuses the move, a macOS access-list entry the run
// could not take away) may put an older generation file and its allows
// back once the run stops. So the lifecycle puts a hold next to the folder,
// <root>.hold, before it changes the folder, in the folder above it, which
// only root/SYSTEM, Administrators or the gateway service can change and
// which the hook already requires to be such a folder. While anything is at
// that path, or the hook cannot tell, the hook allows nothing during an
// outage. The lifecycle removes the hold only after the folder was replaced
// or closed and its generation bumped, so a failed run leaves it in place
// until a later run succeeds.

// publishedSessionHoldSuffix names the hold of a record folder: its path
// with this suffix, next to it.
const publishedSessionHoldSuffix = ".hold"

// publishedSessionHoldLstat reads the hold path (replaceable in tests,
// which stand in for a lifecycle that finishes while the hook checks).
var publishedSessionHoldLstat = os.Lstat

// PublishedSessionHoldPath is the hold of the record folder root.
func PublishedSessionHoldPath(root string) (string, bool) {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return "", false
	}
	root = filepath.Clean(root)
	if root == filepath.Dir(root) {
		return "", false
	}
	return root + publishedSessionHoldSuffix, true
}

// HoldPublishedSessionRecords puts the hold of the record folder root in
// place: from now on the hook allows nothing during an outage, until
// ReleasePublishedSessionRecords. Anything already at the hold path holds.
// The folder above root must exist.
func HoldPublishedSessionRecords(root string) error {
	path, ok := PublishedSessionHoldPath(root)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	if _, err := os.Lstat(path); err == nil {
		return nil
	}
	if err := createPublishedSessionHold(path, publishedSessionHoldText); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

// publishedSessionHoldText only explains the hold file: an empty one holds
// just the same.
const publishedSessionHoldText = "A DefenseClaw lifecycle run is replacing or closing the protected foreign-hook session records next to this file, " +
	"or could not finish doing so. While this file exists, guarded connectors block during a gateway outage. Run the DefenseClaw repair.\n"

// ReleasePublishedSessionRecords removes the hold of the record folder
// root, once the folder was replaced or closed and its generation bumped.
func ReleasePublishedSessionRecords(root string) error {
	path, ok := PublishedSessionHoldPath(root)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s is still there", path)
	}
	return nil
}

// PublishedSessionHeld reports whether the record folder root is held:
// anything is at its hold path, or the path cannot be checked.
func PublishedSessionHeld(root string) bool {
	path, ok := PublishedSessionHoldPath(root)
	if !ok {
		return true
	}
	_, err := publishedSessionHoldLstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

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
