// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"os"
	"path/filepath"
)

// AdminE2fsprogsTools are the e2fsprogs tools the macOS MicroVM driver
// formats every MicroVM's disks with.
var AdminE2fsprogsTools = []string{"mke2fs", "debugfs"}

// AdminE2fsprogsToolDir is the folder the MicroVM driver gets e2fsprogs
// from under the administrator's enterprise.openshell.e2fsprogs_dir: its
// sbin or bin (an e2fsprogs install prefix, the layout of Homebrew's keg
// and of make install), else the folder itself when it holds the tools.
// The first of them holding both mke2fs and debugfs wins, so the one folder
// the gateway puts first on its PATH has both. ensure checks this folder and
// the gateway's exec shim runs with it: one rule, so ensure never accepts a
// directory the gateway then refuses (GAP-0506). "" when none holds both.
// isFile reports whether a path names a regular file (RegularFile; ensure
// maps the path below its root first).
func AdminE2fsprogsToolDir(dir string, isFile func(path string) bool) string {
	if dir == "" {
		return ""
	}
	for _, candidate := range []string{filepath.Join(dir, "sbin"), filepath.Join(dir, "bin"), dir} {
		found := true
		for _, tool := range AdminE2fsprogsTools {
			if !isFile(filepath.Join(candidate, tool)) {
				found = false
				break
			}
		}
		if found {
			return candidate
		}
	}
	return ""
}

// RegularFile reports whether path, after its links, is a regular file.
func RegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
