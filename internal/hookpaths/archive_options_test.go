// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

func TestTarOptionScope(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "proj")
	rows := []struct {
		name  string
		args  []string
		want  string
		known bool
	}{
		{"strip joined", []string{"-xf", "pkg.tar", "--strip-components=1", "-C", "build"}, "build", true},
		{"strip separate", []string{"-xf", "pkg.tar", "--strip-components", "1", "-C", "build"}, "build", true},
		{"exclude joined", []string{"-xf", "pkg.tar", "--exclude=docs", "-C", "build"}, "build", true},
		{"exclude separate", []string{"-xf", "pkg.tar", "--exclude", "docs", "-C", "build"}, "build", true},
		{"auto compress", []string{"-a", "-xf", "pkg.tar", "-C", "build"}, "build", true},
		{"compression flags", []string{"-zjJ", "--zstd", "-xf", "pkg.tar", "-C", "build"}, "build", true},
		{"ordinary flags", []string{"--wildcards", "--overwrite", "--keep-old-files", "--skip-old-files", "--no-same-owner", "--no-same-permissions", "--verbose", "--extract", "-f", "pkg.tar", "-C", "build"}, "build", true},
		{"archive value", []string{"-x", "--file", "-P", "-C", "build"}, "build", true},
		{"command option", []string{"-xf", "pkg.tar", "--to-command", "cat", "-C", "build"}, "", false},
		{"compressor option", []string{"-xf", "pkg.tar", "--use-compress-program", "cat", "-C", "build"}, "", false},
		{"checkpoint option", []string{"-xf", "pkg.tar", "--checkpoint-action=exec=cat", "-C", "build"}, "", false},
		{"transform option", []string{"-xf", "pkg.tar", "--transform", "s/a/b/", "-C", "build"}, "", false},
		{"xform option", []string{"-xf", "pkg.tar", "--xform=s/a/b/", "-C", "build"}, "", false},
		{"absolute names", []string{"-P", "-xf", "pkg.tar", "-C", "build"}, "", false},
		{"absolute names long", []string{"--absolute-names", "-xf", "pkg.tar", "-C", "build"}, "", false},
		{"compressor short", []string{"-I", "cat", "-xf", "pkg.tar", "-C", "build"}, "", false},
		{"unknown option", []string{"--future-option", "-xf", "pkg.tar", "-C", "build"}, "", false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			destination, known := tarDestination(row.args, makeStatic(len(row.args)), cwd)
			if known != row.known || known && destination != row.want {
				t.Fatalf("destination = %q, known = %v", destination, known)
			}
		})
	}
}
