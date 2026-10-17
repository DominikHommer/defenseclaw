// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// ComparisonKey returns one spelling of path for use as a map key, so
// spellings that name the same file share it: the \\?\ and \\?\UNC\
// prefixes are dropped, an existing 8.3 short name is expanded to its long
// name, and the result is cleaned and lower-cased. It is a key, never a
// path to open. Keys that differed by spelling let a second WinGet scan of
// one folder start while the first was stuck, and kept a guardian's pending
// restores apart (GAP-0626).
func ComparisonKey(path string) string {
	path = filepath.FromSlash(strings.TrimSpace(path))
	if path == "" {
		return ""
	}
	if long, ok := longPathName(path); ok {
		path = long
	}
	switch {
	case strings.HasPrefix(path, `\\?\UNC\`):
		path = `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
	case strings.HasPrefix(path, `\\?\`):
		path = strings.TrimPrefix(path, `\\?\`)
	}
	return strings.ToLower(filepath.Clean(path))
}

// longPathName expands the 8.3 short-name components of an existing path.
func longPathName(path string) (string, bool) {
	if !strings.Contains(path, "~") {
		return "", false
	}
	short, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", false
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(short, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		return "", false
	}
	return windows.UTF16ToString(buffer[:n]), true
}
