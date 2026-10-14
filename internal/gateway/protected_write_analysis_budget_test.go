// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestProtectedWriteAnalysisLimit(t *testing.T) {
	home := t.TempDir()
	var assignments strings.Builder
	for i := range 500 {
		fmt.Fprintf(&assignments, "v%d=value%d; ", i, i)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"large_range", `printf '%s\n' {1..100000} > out.txt`, true},
		{"long_list", assignments.String() + `printf ok > out.txt`, true},
		{"small_range", `printf '%s\n' {1..30} > out.txt`, false},
	}
	for _, row := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "/per_user", true: "/managed"}[managed], func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: filepath.Join(home, "project"), ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				request := trustedActionRequest{Input: input, ProtectedHomeHook: managed}
				if managed {
					request.ResolvedWriteTargets = map[string]string{hookpaths.CWDKey: input.CWD}
				}
				if got := trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)); got != row.block {
					t.Fatalf("decision blocked=%v, want %v", got, row.block)
				}
			})
		}
	}
}
