// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTarCommandOptionEvidence(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		incomplete    bool
	}{
		{"checkpoint", `tar -cf out/a.tar --checkpoint=1 --checkpoint-action='exec=printf x >> disklink' payload`, true},
		{"checkpoint_prefix", `tar -cf out/a.tar --checkp-action='exec=printf x >> disklink' payload`, true},
		{"command_output", `tar -xf archive.tar --to-command='printf x >> disklink'`, true},
		{"compressor", `tar -I 'sh -c "printf x >> disklink"' -cf out/a.tar payload`, true},
		{"compressor_long", `tar --use-compress-program 'sh -c "printf x >> disklink"' -cf out/a.tar payload`, true},
		{"volume", `tar -cf out/a.tar -F 'sh -c "printf x >> disklink"' payload`, true},
		{"volume_long", `tar -cf out/a.tar --new-volume-script='sh -c "printf x >> disklink"' payload`, true},
		{"remote", `tar -cf out/a.tar --rmt-command='sh -c "printf x >> disklink"' payload`, true},
		{"remote_shell", `tar -cf out/a.tar --rsh-command='sh -c "printf x >> disklink"' payload`, true},
		{"remote_short", `tar -cf out/a.tar -e 'sh -c "printf x >> disklink"' payload`, true},
		{"transform", `tar -xf archive.tar --transform='s,a,b,e'`, true},
		{"transform_alias", `tar -xf archive.tar --xform='s,a,b,e'`, true},
		{"transform_short", `tar -xf archive.tar -s 's,a,b,e'`, true},
		{"launcher", `env -i tar -cf out/a.tar --checkpoint-action='exec=printf x >> disklink' payload`, true},
		{"shell_string", `bash -c 'tar -cf out/a.tar --checkpoint-action="exec=printf x >> disklink" payload'`, true},
		{"ordinary_create", `tar -cf out/a.tar --checkpoint=1 --totals -v payload`, false},
		{"ordinary_transform", `tar -cf out/a.tar --transform='s,a,b,g' payload`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd, "tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			facts, ok := Decode(Resolve(payload))
			if !ok {
				t.Fatal("invalid analysis evidence")
			}
			_, incomplete := facts[TruncatedKey]
			if incomplete != row.incomplete {
				t.Fatalf("incomplete=%v, want %v", incomplete, row.incomplete)
			}
		})
	}
}
