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

func TestProtectedWriteArchiveCommandOptions(t *testing.T) {
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
		{"checkpoint", `tar -cf out/a.tar --checkpoint=1 --checkpoint-action='exec=printf x >> disklink' payload`, true},
		{"command_output", `tar -xf archive.tar --to-command='printf x >> disklink'`, true},
		{"compressor", `tar -I 'sh -c "printf x >> disklink"' -cf out/a.tar payload`, true},
		{"volume", `tar -cf out/a.tar -F 'sh -c "printf x >> disklink"' payload`, true},
		{"remote", `tar -cf out/a.tar --rmt-command='sh -c "printf x >> disklink"' payload`, true},
		{"remote_shell", `tar -cf out/a.tar --rsh-command='sh -c "printf x >> disklink"' payload`, true},
		{"transform", `tar -xf archive.tar --transform='s,a,b,e'`, true},
		{"launcher", `env -i tar -cf out/a.tar --checkpoint-action='exec=printf x >> disklink' payload`, true},
		{"shell_string", `bash -c 'tar -cf out/a.tar --checkpoint-action="exec=printf x >> disklink" payload'`, true},
		{"ordinary_create", `tar -cf out/a.tar --checkpoint=1 --totals -v payload`, false},
		{"ordinary_transform", `tar -cf out/a.tar --transform='s,a,b,g' payload`, false},
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
