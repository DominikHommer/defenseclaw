// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLauncherScriptTextEvidence(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := filepath.Join(home, "proj")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(key), filepath.Join(project, "tmp"), filepath.Join(project, "out")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(key, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(project, "disklink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"nested_prefixes", `printf x | ` + strings.Repeat("env ", 17) + `tee -a disklink`, true},
		{"nested_limit", `printf x | ` + strings.Repeat("env ", 65) + `tee -a disklink`, true},
		{"stdin_terminator", "bash -- <<'EOF'\nprintf x >> disklink\nEOF", true},
		{"wrapped_stdin", "command bash -- <<'EOF'\nprintf x >> disklink\nEOF", true},
		{"stdin_dash", "sh - <<'EOF'\nprintf x >> disklink\nEOF", true},
		{"stdin_option", "bash -s <<'EOF'\nprintf x >> disklink\nEOF", true},
		{"startup_file", `printf 'printf x >> disklink\n' > tmp/init.sh; BASH_ENV=tmp/init.sh bash -c ':'`, true},
		{"written_interpreter_file", "cat > tmp/run.py <<'EOF'\nopen('disklink','a').write('x')\nEOF\npython3 tmp/run.py", true},
		{"written_shell_input", `printf 'printf x >> disklink\n' > tmp/run.sh; bash < tmp/run.sh`, true},
		{"wrapped_written_shell_input", `printf 'printf x >> disklink\n' > tmp/run.sh; command bash - < tmp/run.sh`, true},
		{"ordinary_written_shell_input", `printf 'printf x >> out/log\n' > tmp/run.sh; bash < tmp/run.sh`, false},
		{"numa_option", `numactl -C 0 tee -a disklink`, true},
		{"taskset_attached", `taskset -c0-1024 tee -a disklink`, true},
		{"taskset_separate", `taskset -c 0 tee -a disklink`, true},
		{"schedtool_option", `schedtool -n 0 -e tee -a disklink`, true},
		{"cpulimit_option", `cpulimit -l 50 -- tee -a disklink`, true},
		{"prlimit_option", `prlimit --nproc=100 -- tee -a disklink`, true},
		{"group_script", `sg staff -c 'printf x >> disklink'`, true},
		{"unknown_option", `numactl --not-listed tee -a disklink`, true},
		{"ordinary_stdin", "bash -- <<'EOF'\nprintf x >> out/log\nEOF", false},
		{"ordinary_numa", `numactl -C 0 tee -a out/log`, false},
		{"ordinary_taskset", `taskset -c0-1024 tee -a out/log`, false},
		{"ordinary_taskset_separate", `taskset -c 0 tee -a out/log`, false},
		{"ordinary_cpulimit", `cpulimit -l 50 -- tee -a out/log`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			facts, ok := Decode(Resolve(payload))
			if !ok {
				t.Fatal("invalid analysis evidence")
			}
			blocked := facts[TruncatedKey] == "1"
			for _, target := range facts {
				if target == key {
					blocked = true
				}
			}
			if blocked != row.block {
				t.Fatalf("protected write evidence=%v, want %v", blocked, row.block)
			}
		})
	}
}
