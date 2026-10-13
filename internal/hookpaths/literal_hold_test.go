// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestLiteralWriterHoldout(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "proj")
	home := filepath.Dir(cwd)
	protected := filepath.Join(cwd, "disklink")
	rows := []struct {
		name, command string
		want          bool
	}{
		{"python module", `python3 -c 'import builtins; builtins.open("disklink","a").write("x")'`, true},
		{"python builtin module", `python3 -c '__builtins__.open("disklink","a").write("x")'`, true},
		{"python import binding", `python3 -c 'from builtins import open as save; save("disklink","a").write("x")'`, true},
		{"python assigned binding", `python3 -c 'import builtins; save=builtins.open; save("disklink","a").write("x")'`, true},
		{"python path touch", `python3 -c 'from pathlib import Path; Path("disklink").touch()'`, true},
		{"node append open", `node -e 'require("fs").openSync("disklink","a")'`, true},
		{"node numeric open", `node -e 'require("fs").openSync("disklink",1)'`, true},
		{"perl module switch", `perl -MFile::Copy -e 'copy("payload","disklink")'`, true},
		{"perl named import", `perl -MFile::Copy=copy,move -e 'move("payload","disklink")'`, true},
		{"perl qualified module", `perl -mFile::Copy -e 'File::Copy::copy("payload","disklink")'`, true},
		{"perl truncate", `perl -e 'truncate("disklink",3)'`, true},
		{"ruby truncate", `ruby -e 'File.truncate("disklink",3)'`, true},
		{"ruby required module", `ruby -rfileutils -e 'FileUtils.cp("payload","disklink")'`, true},
		{"python ordinary", `python3 -c 'import builtins; builtins.open("notes.txt","a").write("x")'`, false},
		{"python read", `python3 -c 'import builtins; builtins.open("disklink","r").read()'`, false},
		{"node read open", `node -e 'require("fs").openSync("disklink","r")'`, false},
		{"node zero flags", `node -e 'require("fs").openSync("disklink",0)'`, false},
		{"node read flag", `node -e 'const fs=require("fs"); fs.openSync("disklink",fs.constants.O_RDONLY)'`, false},
		{"perl module read", `perl -MFile::Copy -e 'open(my $fh,"<","disklink")'`, false},
		{"perl module without import", `perl -mFile::Copy -e 'copy("payload","disklink")'`, false},
		{"ruby ordinary", `ruby -e 'File.truncate("notes.txt",3)'`, false},
		{"ruby required module ordinary", `ruby -rfileutils -e 'FileUtils.cp("payload","notes.txt")'`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := slices.Contains(LiteralWriteOperands(row.command, cwd, home), protected); got != row.want {
				t.Fatalf("target listed = %v, want %v", got, row.want)
			}
		})
	}
}
