// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestProtectedWritePositionalValueChanges(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(key), filepath.Join(cwd, "out")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(key, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"shift_one", `set -- unused disklink; shift; echo x >> "$1"`, true},
		{"shift_two", `set -- a b disklink; shift 2; echo x >> "$1"`, true},
		{"function_shift", `f(){ shift; echo x >> "$1"; }; f unused disklink`, true},
		{"child_shift", `bash -c 'shift; echo x >> "$1"' _ unused disklink`, true},
		{"subshell_shift", `set -- unused disklink; (shift; echo x >> "$1")`, true},
		{"guarded_shift", `set -- unused disklink; if true; then shift; fi; echo x >> "$1"`, true},
		{"safe_shift", `set -- unused out/a; shift; echo x >> "$1"`, false},
		{"outer_scope", `set -- out/a disklink; (shift); echo x >> "$1"`, false},
	}
	for _, row := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "/per_user", true: "/managed"}[managed], func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				request := trustedActionRequest{Input: input, ProtectedHomeHook: managed}
				if managed {
					request.ResolvedWriteTargets = map[string]string{hookpaths.CWDKey: cwd}
				}
				if blocked := trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)); blocked != row.block {
					t.Fatalf("decision blocked=%v, want %v", blocked, row.block)
				}
			})
		}
	}
}
