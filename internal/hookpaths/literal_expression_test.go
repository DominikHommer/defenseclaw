// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestLiteralWriterExpressions(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	protected := filepath.Join(home, ".ssh", "authorized_keys2")
	ordinary := filepath.Join(project, "build", "report.txt")
	rows := []struct {
		name, command string
		block         bool
	}{
		{"python_joined", `python3 -c 'open("../.ssh/" + "authorized_keys2","a").write("x")'`, true},
		{"python_adjacent", `python3 -c 'open("../.ssh/" "authorized_keys2","a").write("x")'`, true},
		{"python_path_join", `python3 -c 'import os; open(os.path.join("..",".ssh","authorized_keys2"),"a").write("x")'`, true},
		{"python_path_division", `python3 -c 'from pathlib import Path; (Path("..")/".ssh"/"authorized_keys2").write_text("x")'`, true},
		{"python_percent", `python3 -c 'open("../.ssh/%s" % "authorized_keys2","a").write("x")'`, true},
		{"python_format", `python3 -c 'open("../.ssh/{}".format("authorized_keys2"),"a").write("x")'`, true},
		{"python_fstring", `python3 -c "open(f'../.ssh/{\"authorized_keys2\"}','a').write('x')"`, true},
		{"node_joined", `node -e 'require("fs").writeFileSync("../.ssh/"+"authorized_keys2","x")'`, true},
		{"node_path_join", `node -e 'require("fs").writeFileSync(require("path").join("..",".ssh","authorized_keys2"),"x")'`, true},
		{"node_template", "node -e 'require(\"fs\").writeFileSync(`../.ssh/${\"authorized_keys2\"}`,\"x\")'", true},
		{"perl_joined", `perl -e 'open(F,">>","../.ssh/" . "authorized_keys2"); print F "x"'`, true},
		{"perl_join", `perl -e 'open(F,">>",join("/","..",".ssh","authorized_keys2")); print F "x"'`, true},
		{"perl_sprintf", `perl -e 'open(F,">>",sprintf("../.ssh/%s","authorized_keys2")); print F "x"'`, true},
		{"ruby_joined", `ruby -e 'File.write("../.ssh/" + "authorized_keys2","x")'`, true},
		{"ruby_file_join", `ruby -e 'File.write(File.join("..",".ssh","authorized_keys2"),"x")'`, true},
		{"awk_joined", `gawk 'BEGIN{a="../.ssh/"; b="authorized_keys2"; print "x" >> (a b)}'`, true},
		{"python_project_joined", `python3 -c 'open("build/" + "report.txt","a").write("x")'`, false},
		{"python_project_adjacent", `python3 -c 'open("build/" "report.txt","a").write("x")'`, false},
		{"python_project_path_join", `python3 -c 'import os; open(os.path.join("build","report.txt"),"a").write("x")'`, false},
		{"python_project_path_division", `python3 -c 'from pathlib import Path; (Path("build")/"report.txt").write_text("x")'`, false},
		{"python_project_percent", `python3 -c 'open("build/%s" % "report.txt","a").write("x")'`, false},
		{"python_project_format", `python3 -c 'open("build/{}".format("report.txt"),"a").write("x")'`, false},
		{"python_project_fstring", `python3 -c "open(f'build/{\"report.txt\"}','a').write('x')"`, false},
		{"node_project_joined", `node -e 'require("fs").writeFileSync("build/"+"report.txt","x")'`, false},
		{"node_project_path_join", `node -e 'require("fs").writeFileSync(require("path").join("build","report.txt"),"x")'`, false},
		{"node_project_template", "node -e 'require(\"fs\").writeFileSync(`build/${\"report.txt\"}`,\"x\")'", false},
		{"perl_project_joined", `perl -e 'open(F,">>","build/" . "report.txt"); print F "x"'`, false},
		{"perl_project_join", `perl -e 'open(F,">>",join("/","build","report.txt")); print F "x"'`, false},
		{"perl_project_sprintf", `perl -e 'open(F,">>",sprintf("build/%s","report.txt")); print F "x"'`, false},
		{"ruby_project_joined", `ruby -e 'File.write("build/" + "report.txt","x")'`, false},
		{"ruby_project_file_join", `ruby -e 'File.write(File.join("build","report.txt"),"x")'`, false},
		{"awk_project_joined", `gawk 'BEGIN{a="build/"; b="report.txt"; print "x" >> (a b)}'`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, unknown := LiteralWriteAnalysis(row.command, project, home)
			want := ordinary
			if row.block {
				want = protected
			}
			if unknown || !slices.Contains(paths, want) {
				t.Fatalf("literal writer paths=%v unknown=%v, want exact target", paths, unknown)
			}
		})
	}
	if _, ok := literalString(`"build/"+"report.txt"`); ok {
		t.Fatal("a combined expression was treated as one literal")
	}
	for _, expression := range []string{`"../.ssh/" + suffix`, `path.join("..", name)`, `"../.ssh/" . $name`} {
		for _, language := range []string{"python", "node", "perl"} {
			if _, ok := literalExpression(language, expression); ok {
				t.Errorf("%s expression %q was treated as exact", language, expression)
			}
		}
	}
}
