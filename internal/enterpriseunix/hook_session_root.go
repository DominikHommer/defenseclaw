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

package enterpriseunix

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// hookSessionRetiredInfix names a record folder the lifecycle replaced:
// .<folder name>.retired-<nanoseconds>, next to the folder. The hook never
// reads it.
const hookSessionRetiredInfix = ".retired-"

// hookSessionRename moves the record folder aside (replaceable in tests,
// which stand in for a rename the system refuses).
var hookSessionRename = os.Rename

// hookSessionTreeACLWritable reports whether a macOS access-list entry lets
// another account change the record folder at path or anything in it: the
// generation file, the account folders and their records. Entries are
// inherited: one an account set on the folder while it owned it goes to
// every folder and record the gateway creates in it, and stays there when
// the folder's own entry goes. An access list that cannot be read counts as
// one that does. The gateway's read-only entry for each account's own folder
// does not.
func (l *lifecycle) hookSessionTreeACLWritable(ctx context.Context, path string) bool {
	targets := []aclTarget{{path: path}}
	walkErr := filepath.WalkDir(path, func(entry string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry == path {
			return nil
		}
		if d.Type()&fs.ModeSymlink == 0 && (d.IsDir() || d.Type().IsRegular()) {
			targets = append(targets, aclTarget{path: entry})
		}
		if d.IsDir() && filepath.Dir(entry) != path {
			// The records are one level below the account folders.
			return fs.SkipDir
		}
		return nil
	})
	findings, err := l.env.aclFindings(ctx, targets)
	return walkErr != nil || err != nil || len(findings) > 0
}

// replaceHookSessionRoot moves the record folder at path aside, with
// everything in it, and puts a new, empty one closed to other accounts
// (closeHookSessionRoot) in its place. No entry of the old folder's access
// list, nor of anything in it, comes with it, and no account can bring the
// old folder back: the folder above is one no other account can change
// (applyDirs closed it, or it was already right). The old folder is removed;
// one that cannot be removed now goes at the next replacement.
func (e *Env) replaceHookSessionRoot(path string, owner fileOwner) error {
	retired := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+hookSessionRetiredInfix+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := hookSessionRename(path, retired); err != nil {
		return fmt.Errorf("move it aside: %w", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := e.closeHookSessionRoot(path, owner); err != nil {
		return err
	}
	removeRetiredHookSessionRoots(path)
	return nil
}

// removeRetiredHookSessionRoots removes the record folders replaced next to
// path. Best effort: the hook never reads them.
func removeRetiredHookSessionRoots(path string) {
	parent := filepath.Dir(path)
	prefix := "." + filepath.Base(path) + hookSessionRetiredInfix
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) && entry.IsDir() {
			_ = os.RemoveAll(filepath.Join(parent, entry.Name()))
		}
	}
}
