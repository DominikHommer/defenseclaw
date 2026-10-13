// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInlineInterpreterProtectedUses(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), cwd, filepath.Join(cwd, "out")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		command string
		block   bool
	}{
		{`python3 -c 'import logging; logging.basicConfig(filename="disklink", level=10); logging.info("x")'`, true},
		{`python3 -c 'import logging; h=logging.FileHandler("disklink"); h.stream.write("x")'`, true},
		{`python3 -c 'exec("open(\"disklink\",\"a\").write(\"x\")")'`, true},
		{`node -e 'const w=require("fs").writeFileSync; w("disklink","x")'`, true},
		{`node -e 'import("fs").then(f=>f.appendFileSync("disklink","x"))'`, true},
		{`node -e 'eval("require(\"fs\").appendFileSync(\"disklink\",\"x\")")'`, true},
		{`node -e 'require("child_process").spawnSync("cp",["payload","disklink"])'`, true},
		{`perl -e '$f="disklink"; open(F,">>$f"); print F "x"'`, true},
		{`awk -v f=disklink 'BEGIN{print "x" >> f}'`, true},
		{`awk 'BEGIN{print "x" | "tee -a disklink"}'`, true},
		{`python3 -c 'print(open("disklink").read())'`, false},
		{`node -e 'console.log(require("fs").readFileSync("disklink","utf8"))'`, false},
		{`python3 -c 'print("disklink")'`, false},
		{`awk -v f=disklink 'BEGIN{print f}'`, false},
	}
	for _, row := range rows {
		t.Run(row.command, func(t *testing.T) {
			paths, unknown := LiteralWriteAnalysis(row.command, cwd, home)
			blocked := unknown
			for _, path := range paths {
				resolved, ok := ResolveWriteTarget(path)
				if ok && resolved == keys {
					blocked = true
				}
			}
			if blocked != row.block {
				t.Errorf("blocked = %v, want %v", blocked, row.block)
			}
		})
	}
}
