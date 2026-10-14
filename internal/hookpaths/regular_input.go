// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"os"
)

// readRegularCommandFile reads a small, stable regular file named by command
// text. Special files and changed files remain unknown to the analysis.
func readRegularCommandFile(path string, limit int64) ([]byte, bool) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, false
	}
	file, err := openRegularNoFollow(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() < 0 || after.Size() > limit || !os.SameFile(before, after) {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, false
	}
	return data, true
}
