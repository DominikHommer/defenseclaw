// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// trustedTreeMaxEntries bounds the walk of a policy tree or rule pack.
const trustedTreeMaxEntries = 20000

var errTrustedTreeTooLarge = errors.New("too many entries")

// walkTrustedTree calls check for every folder and file below root (root
// itself excluded: the caller checks it with its parents) without following
// links, and stops at the first refusal. A link reaches check as a file, so
// the file check refuses it.
func walkTrustedTree(root string, check func(path string, isDir bool) error) error {
	entries := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entries++; entries > trustedTreeMaxEntries {
			return errTrustedTreeTooLarge
		}
		return check(path, entry.IsDir())
	})
	if errors.Is(err, errTrustedTreeTooLarge) {
		return fmt.Errorf("%s has more than %d entries", root, trustedTreeMaxEntries)
	}
	return err
}
