// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestProtectedWriteLiteralWriterDecisions(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
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
		{"python destination", `python3 -c 'import shutil as s; s.copy2("source","disklink")'`, true},
		{"python file object", `env -i python3 -c 'import io; io.FileIO("disklink","w")'`, true},
		{"node asynchronous", `node -e 'require("fs").writeFile("disklink","x",()=>{})'`, true},
		{"node copy", `node -e 'require("fs").copyFileSync("source","disklink")'`, true},
		{"perl copy", `perl -e 'use File::Copy; copy("source","disklink")'`, true},
		{"ruby copy", `ruby -e 'require "fileutils"; FileUtils.cp("source","disklink")'`, true},
		{"python directory copy", `python3 -c 'import shutil; shutil.copytree("tree","../.ssh",dirs_exist_ok=True)'`, true},
		{"python file into directory", `python3 -c 'import shutil; shutil.copy("authorized_keys","../.ssh")'`, true},
		{"node directory copy", `node -e 'require("fs").cpSync("tree","../.ssh",{recursive:true})'`, true},
		{"dynamic destination", `python3 -c 'p="disklink"; open(p,"w").write("x")'`, true},
		{"python ordinary", `python3 -c 'import shutil; shutil.copy2("source","notes.txt")'`, false},
		{"node read", `node -e 'require("fs").readFileSync("disklink")'`, false},
		{"node append open", `node -e 'require("fs").openSync("disklink","a")'`, false},
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

func TestProtectedWriteLiteralWindowsDecisions(t *testing.T) {
	home := `C:\Users\b00`
	cwd := home + `\proj`
	rows := []struct {
		name, command string
		dialect       actionfacts.Dialect
		want          bool
	}{
		{"python file object", `python -c "import io; io.FileIO('../.ssh/authorized_keys','w')"`, actionfacts.DialectCMD, true},
		{"node copy", `node -e "require('fs').copyFileSync('payload','../.ssh/authorized_keys')"`, actionfacts.DialectCMD, true},
		{"perl copy", `perl -e "use File::Copy; copy('payload','../.ssh/authorized_keys')"`, actionfacts.DialectCMD, true},
		{"posix interpreter", `python3 -c 'import io; io.FileIO("../.ssh/authorized_keys","w")'`, "", true},
		{"node read", `node -e "require('fs').readFileSync('../.ssh/authorized_keys')"`, actionfacts.DialectCMD, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": row.command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: "Bash", Args: args, CWD: cwd, ActiveHome: home, DialectHint: row.dialect}
			request := trustedActionRequest{Input: input, ProtectedHomeHook: true}
			if got := trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)); got != row.want {
				t.Fatalf("decision = %v, want %v", got, row.want)
			}
		})
	}
}
