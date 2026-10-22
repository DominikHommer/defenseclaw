// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package copilotargs

import (
	"strings"
	"testing"
)

func TestPermissionEditArgsRequiresOneCompleteDeclaredDiff(t *testing.T) {
	const path = "/home/alice/project/notes.txt"
	base := "\ndiff --git a" + path + " b" + path + "\nindex 1234567..abcdef0 100644\n--- a" + path +
		"\n+++ b" + path + "\n@@ -1 +1 @@\n-old\n+new\n"
	for _, tc := range []struct {
		name, diff string
		valid      bool
	}{
		{"single file", base, true},
		{"two complete hunks", base + "@@ -3 +3 @@\n-before\n+after\n", true},
		{"second file", base + "diff --git a" + path + " b" + path + "\n", false},
		{"mismatched target", strings.Replace(base, "+++ b"+path, "+++ b/home/alice/project/other.txt", 1), false},
		{"missing line", strings.Replace(base, "+new\n", "", 1), false},
		{"extra line", base + "+hidden\n", false},
		{"rename metadata", strings.Replace(base, "index 1234567..abcdef0 100644", "rename from other.txt", 1), false},
		{"bare carriage return", base + "\r", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := PermissionEditArgs("edit", map[string]any{"file_path": path, "diff": tc.diff})
			if (len(got) > 0) != tc.valid {
				t.Fatalf("projected=%s, valid=%t", got, tc.valid)
			}
		})
	}
	if got := PermissionEditArgs("edit", map[string]any{"file_path": path, "diff": base, "another_path": "/tmp/hidden"}); len(got) != 0 {
		t.Fatalf("extra target became trusted: %s", got)
	}
}
