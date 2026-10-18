// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shellProjectGlobCandidates bounds one literal project-directory glob in a
// top-level loop. ReadDir includes dot entries as a conservative superset of
// shell glob modes. No statement runs before expansion in this shell shape.
func shellProjectGlobCandidates(file *syntax.File, loop *syntax.ForClause, word *syntax.Word, cwd string) ([]string, bool) {
	if file == nil || len(file.Stmts) != 1 || file.Stmts[0].Cmd != loop ||
		!filepath.IsAbs(cwd) || word == nil || len(word.Parts) != 1 {
		return nil, false
	}
	lit, ok := word.Parts[0].(*syntax.Lit)
	if !ok || !strings.HasSuffix(lit.Value, "/*") {
		return nil, false
	}
	prefix := strings.TrimSuffix(lit.Value, "/*")
	if prefix == "" || filepath.IsAbs(prefix) ||
		strings.ContainsAny(prefix, "*?[]$`~\\\x00\r\n") {
		return nil, false
	}
	for _, component := range strings.Split(filepath.ToSlash(prefix), "/") {
		if component == ".." || component == "." || component == "" {
			return nil, false
		}
	}
	directory := OperandPath(prefix, cwd)
	if !strings.HasPrefix(directory, cwd+string(filepath.Separator)) {
		return nil, false
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > MaxWriteTargets {
		return nil, false
	}
	if len(entries) == 0 {
		return []string{lit.Value}, true // Bash preserves an unmatched glob.
	}
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "." || name == ".." || strings.ContainsAny(name, "\x00\r\n") {
			return nil, false
		}
		values = append(values, prefix+"/"+name)
	}
	return values, true
}
