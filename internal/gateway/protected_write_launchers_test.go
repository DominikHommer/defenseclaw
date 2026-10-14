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

func TestProtectedWriteLauncherDecisions(t *testing.T) {
	skipWindowsProtectedWritePOSIX(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		want          bool
	}{
		{"env options", `env -i python3 -c 'open("disklink","a").write("x")'`, true},
		{"command prefix", `command -p cp payload disklink`, true},
		{"nested process prefix", `nice -n 5 env A=1 cp payload disklink`, true},
		{"shell command", `bash -c 'cp payload disklink'`, true},
		{"shell positional destination", `sh -c 'tee -a "$1" < payload' _ disklink`, true},
		{"shell positional ordinary", `bash -c 'echo x >> $1' _ out/one`, false},
		{"find child", `find disklink -exec cp payload {} \;`, true},
		{"resolved link target", `tee -a $(readlink -f disklink) < payload`, true},
		{"resolved link ordinary", `cp payload $(readlink -f build)/out`, false},
		{"xargs child", `printf disklink | xargs -I{} cp payload {}`, true},
		{"numa prefix", `numactl --localalloc cp payload disklink`, true},
		{"flock command", `flock lockfile -c 'cp payload disklink'`, true},
		{"child shell target", `f=disklink bash -c 'printf x >> "$f"'`, true},
		{"ordinary env", `env -i python3 -c 'open("notes.txt","a").write("x")'`, false},
		{"ordinary command", `command -p cp payload notes.txt`, false},
		{"ordinary xargs", `printf notes.txt | xargs -I{} cp payload {}`, false},
		{"copy loop bounded source", `for f in *.txt; do cp "$f" build/; done; echo done > report.txt`, false},
		{"copy literal destination", `find . -maxdepth 1 -name payload -print0 | xargs -0 -I{} cp {} disklink`, true},
	}
	for _, row := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "/per-user", true: "/managed"}[managed], func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				request := trustedActionRequest{Input: input, ProtectedHomeHook: managed}
				if managed {
					request.ResolvedWriteTargets = map[string]string{hookpaths.CWDKey: cwd}
				}
				if got := trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)); got != row.want {
					t.Fatalf("decision = %v, want %v", got, row.want)
				}
			})
		}
	}
}
