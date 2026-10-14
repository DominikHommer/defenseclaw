// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestProtectedWriteOrdinaryShellValues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell and symlink fixture")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "build"), filepath.Join(project, "tmp")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(key, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "report.txt"), []byte("report\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "payload"), []byte("payload\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(project, "disklink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command string }{
		{"formatted_directory", `d=$(printf %s "$PWD"); printf x >> "$d/build/report.txt"`},
		{"directory_name", `d=$(dirname "$PWD/build/report.txt"); printf x >> "$d/report.txt"`},
		{"finite_loop", `for n in one two; do out="build/${n}.txt"; printf x >> "$out"; done`},
		{"range_loop", `for n in {1..257}; do printf x > "build/v${n}.txt"; done`},
		{"written_script", "python3 - <<'PY'\n" + strings.Repeat("# project note\n", 2000) + "open('build/report.txt','w').write('x')\nPY"},
		{"bounded_link", `L=ln; command "$L" -s "$HOME/proj/report.txt" tmp/v6link; printf x >> tmp/v6link`},
		{"ordinary_eval", `dest=build/report.txt; eval "dest=build/report.txt"; printf x >> "$dest"`},
		{"literal_xargs", `printf 'build/report.txt\n' | xargs -n1 sh -c 'printf x >> "$0"'`},
		{"reader_pipeline", `rg -n apply_patch build/report.txt | cat`},
		{"reader_sequence", `rg -n apply_patch build/report.txt; printf done`},
		{"reader_status", `rg -n apply_patch build/report.txt; true`},
	}
	for _, row := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "/per_user", true: "/managed"}[managed], func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: project, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				request := trustedActionRequest{Input: input, ProtectedHomeHook: managed}
				if managed {
					payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": input.Command}})
					if err != nil {
						t.Fatal(err)
					}
					request.ResolvedWriteTargets, _ = hookpaths.Decode(hookpaths.Resolve(payload))
				}
				if trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) {
					t.Fatal("ordinary project command blocked")
				}
			})
		}
	}
	for _, row := range []struct{ name, command string }{
		{"finite_copy_target", `for n in disklink build/report.txt; do cp payload "$n"; done`},
		{"finite_redirect_target", `for n in disklink build/report.txt; do printf x >> "$n"; done`},
		{"known_home_target", `d=$(printf %s "$HOME"); printf x >> "$d/.ssh/authorized_keys"`},
		{"eval_target", `eval "dest=../.ssh/authorized_keys"; printf x >> "$dest"`},
		{"literal_xargs_target", `printf 'disklink\n' | xargs -n1 sh -c 'printf x >> "$0"'`},
		{"bounded_link_target", `L=ln; command "$L" -s "$HOME/.ssh/authorized_keys" tmp/key; printf x >> tmp/key`},
	} {
		for _, managed := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "/per_user", true: "/managed"}[managed], func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: project, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				request := trustedActionRequest{Input: input, ProtectedHomeHook: managed}
				if managed {
					payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": input.Command}})
					if err != nil {
						t.Fatal(err)
					}
					request.ResolvedWriteTargets, _ = hookpaths.Decode(hookpaths.Resolve(payload))
				}
				if !trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) {
					t.Fatal("protected target was allowed")
				}
			})
		}
	}
}
