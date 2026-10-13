// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestLiteralWriterClasses(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "proj")
	home := filepath.Dir(cwd)
	target := filepath.Join(cwd, "disklink")
	rows := []struct {
		name, command string
		want          bool
	}{
		{"python copyfile", `python3 -c 'import shutil; shutil.copyfile("payload","disklink")'`, true},
		{"python copy2 alias", `python3 -c 'import shutil as s; s.copy2("payload","disklink")'`, true},
		{"python imported copy", `python3 -c 'from shutil import copy2 as c; c("payload","disklink")'`, true},
		{"python file object", `python3 -c 'import io; io.FileIO("disklink","w")'`, true},
		{"versioned python", `python3.12 -c 'import io; io.FileIO("disklink","w")'`, true},
		{"env python", `env python3 -c 'import io; io.FileIO("disklink","w")'`, true},
		{"python named mode", `python3 -c 'open("disklink",mode="a").write("x")'`, true},
		{"python variable mode", `python3 -c 'mode="w"; open("disklink",mode)'`, true},
		{"python file descriptor", `python3 -c 'import os as o; o.open("disklink",o.O_WRONLY|o.O_CREAT)'`, true},
		{"python path method", `python3 -c 'from pathlib import Path; Path("disklink").write_bytes(b"x")'`, true},
		{"python copytree file", `python3 -c 'import shutil; shutil.copytree("source","disklink")'`, false},
		{"python replace", `python3 -c 'import os; os.replace("source","disklink")'`, true},
		{"node async write", `node -e 'require("fs").writeFile("disklink","x",()=>{})'`, true},
		{"absolute node", `/usr/local/bin/node -e 'require("fs").copyFileSync("source","disklink")'`, true},
		{"node promises write", `node -e 'require("node:fs").promises.writeFile("disklink","x")'`, true},
		{"node promises import", `node -e 'const fsp=require("fs/promises"); fsp.appendFile("disklink","x")'`, true},
		{"node copy sync", `node -e 'require("fs").copyFileSync("source","disklink")'`, true},
		{"node copy alias", `node -e 'const {copyFileSync}=require("fs"); copyFileSync("source","disklink")'`, true},
		{"node esm import", `node --input-type=module --eval 'import { writeFileSync as save } from "node:fs"; save("disklink","x")'`, true},
		{"node stream", `node -e 'require("fs").createWriteStream("disklink")'`, true},
		{"node open truncate", `node -e 'require("fs").openSync("disklink","w")'`, true},
		{"perl copy", `perl -e 'use File::Copy; copy("source","disklink")'`, true},
		{"perl update open", `perl -e 'open(my $fh,"+<disklink"); print $fh "x"'`, true},
		{"perl qualified copy", `perl -e 'File::Copy::copy("source","disklink")'`, true},
		{"perl move", `perl -e 'use File::Copy; move("source","disklink")'`, true},
		{"perl sysopen", `perl -e 'use Fcntl; sysopen(my $fh,"disklink",O_WRONLY|O_CREAT)'`, true},
		{"perl rename", `perl -e 'rename("source","disklink")'`, true},
		{"ruby write", `ruby -e 'File.write("disklink","x")'`, true},
		{"ruby io write", `ruby -e 'IO.binwrite("disklink","x")'`, true},
		{"ruby fileutils copy", `ruby -e 'require "fileutils"; FileUtils.cp("source","disklink")'`, true},
		{"ruby rename", `ruby -e 'File.rename("source","disklink")'`, true},
		{"python read", `python3 -c 'open("disklink").read()'`, false},
		{"python file object read", `python3 -c 'import io; io.FileIO("disklink","r")'`, false},
		{"python ordinary variable mode", `python3 -c 'mode="w"; open("notes.txt",mode)'`, false},
		{"node read", `node -e 'require("fs").readFileSync("disklink")'`, false},
		{"node open append intent", `node -e 'require("fs").openSync("disklink","a")'`, true},
		{"perl read", `perl -e 'open(my $fh,"<","disklink")'`, false},
		{"ruby read", `ruby -e 'File.open("disklink","r")'`, false},
		{"ordinary copy", `python3 -c 'import shutil; shutil.copy2("source","notes.txt")'`, false},
		{"ordinary node", `node -e 'require("fs").copyFileSync("source","notes.txt")'`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := slices.Contains(LiteralWriteOperands(row.command, cwd, home), target)
			if got != row.want {
				t.Fatalf("target listed = %v, want %v", got, row.want)
			}
		})
	}
}

func TestLiteralWriterDynamicDestinations(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "proj")
	home := filepath.Dir(cwd)
	rows := []string{
		`python3 -c 'p="disklink"; open(p,"w").write("x")'`,
		`node -e 'const p="disklink"; require("fs").copyFileSync("source",p)'`,
		`perl -e 'use File::Copy; my $p="disklink"; copy("source",$p)'`,
		`ruby -e 'p="disklink"; IO.binwrite(p,"x")'`,
	}
	for _, command := range rows {
		_, unknown := LiteralWriteAnalysis(command, cwd, home)
		if !unknown {
			t.Errorf("unknown destination not reported for %q", command)
		}
	}
}

func TestLiteralWriterDirectoryDestinations(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "proj")
	home := filepath.Dir(cwd)
	target := filepath.Join(home, ".ssh", "authorized_keys")
	rows := []struct {
		name, command string
		want          bool
	}{
		{"python copytree", `python3 -c 'import shutil; shutil.copytree("tree","../.ssh",dirs_exist_ok=True)'`, true},
		{"python copy directory", `python3 -c 'import shutil; shutil.copy("authorized_keys","../.ssh")'`, true},
		{"python move directory", `python3 -c 'import shutil; shutil.move("authorized_keys","../.ssh")'`, true},
		{"node recursive copy", `node -e 'require("fs").cpSync("tree","../.ssh",{recursive:true})'`, true},
		{"perl copy directory", `perl -e 'use File::Copy; copy("authorized_keys","../.ssh")'`, true},
		{"ruby copy directory", `ruby -e 'require "fileutils"; FileUtils.cp("authorized_keys","../.ssh")'`, true},
		{"ordinary copytree", `python3 -c 'import shutil; shutil.copytree("tree","out/tree")'`, false},
		{"ordinary copy directory", `python3 -c 'import shutil; shutil.copy("authorized_keys","out")'`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := slices.Contains(LiteralWriteOperands(row.command, cwd, home), target)
			if got != row.want {
				t.Fatalf("target listed = %v, want %v", got, row.want)
			}
		})
	}
}
