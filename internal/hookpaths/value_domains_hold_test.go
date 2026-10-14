// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedShellValueDomains(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), cwd, filepath.Join(cwd, "out"), filepath.Join(cwd, "build"), filepath.Join(cwd, "docs")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "payload"), []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		command string
		block   bool
	}{
		{`echo payload | xargs -I{} cp {} disklink`, true},
		{`find . -maxdepth 1 -name payload -print0 | xargs -0 -I{} cp {} disklink`, true},
		{`for f in disk*; do tee -a $f < payload; done`, true},
		{`declare -n r=x; x=disklink; echo x >> $r`, true},
		{"f=`basename $PWD`; cd ..; echo x >> $f/disklink", true},
		{`for f in out/*; do echo x >> $f; done`, false},
		{`x=out; echo x >> ${x:0}/f2`, false},
		{`x=OUT; echo x >> ${x,,}/f3`, false},
		{`x=y; y=out; echo x >> ${!x}/f4`, false},
		{`mapfile -t x < <(echo out); echo x >> ${x[0]}/f7`, false},
		{`f=out/a; [ -e nonexist ] && f=out/b; echo x >> $f`, false},
		{`f=$(printf out)/f9; echo x >> $f`, false},
		{`f=$(basename /x/out)/f10; echo x >> $f`, false},
		{`name="$(basename docs/guide.md)"; cp docs/guide.md "out/$name"`, false},
	}
	for _, row := range rows {
		t.Run(row.command, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd, "tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok {
				t.Fatal("invalid resolution")
			}
			blocked := targets[TruncatedKey] != ""
			for _, value := range targets {
				if value == keys {
					blocked = true
				}
			}
			if blocked != row.block {
				t.Errorf("protected write = %v, want %v; targets=%v", blocked, row.block, targets)
			}
		})
	}
}
