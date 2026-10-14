// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestProgramOutputOperands(t *testing.T) {
	skipWindowsShellFixture(t)
	cwd := "/tmp/project"
	for _, row := range []struct{ command, target string }{
		{"sort -o disklink payload", "disklink"},
		{"wget -q -O disklink file:///tmp/payload", "disklink"},
		{"curl -s file:///tmp/payload --output=disklink", "disklink"},
		{"curl -s file:///tmp/payload -odisklink", "disklink"},
		{"ssh-keygen -q -f disklink -N ''", "disklink"},
		{"git diff --output=disklink", "disklink"},
		{"sqlite3 disklink '.databases'", "disklink"},
		{"openssl rand -out disklink 8", "disklink"},
		{"gpg --output disklink --dearmor payload", "disklink"},
		{"script -q disklink", "disklink"},
		{"strace -o disklink true", "disklink"},
		{"tar -cf disklink payload", "disklink"},
		{"zip disklink payload", "disklink"},
		{"script -q -c 'printf x' disklink", "disklink"},
		{"/usr/bin/time -o disklink true", "disklink"},
		{"sort -o out/sorted payload", "out/sorted"},
		{"wget -O out/file file:///tmp/payload", "out/file"},
	} {
		t.Run(row.command, func(t *testing.T) {
			var got []string
			for _, output := range ShellExtraWriteOperands(row.command, cwd, "/tmp/home") {
				got = append(got, output.Path)
			}
			if !slices.Contains(got, filepath.Join(cwd, row.target)) {
				t.Errorf("outputs = %v", got)
			}
		})
	}
}
