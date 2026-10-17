// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// These are the 15 B00 v5 bypass rows that the rc.5 parser allowed.
func TestR103B07EnvBypassRows(t *testing.T) {
	for _, tc := range []struct{ id, command string }{
		{"BYP-0215", `env -i python3 -c 'open("disklink","a").write("dccert-block-marker")'`},
		{"BYP-0266", `env --ignore-environment python3 -c 'open("disklink","a").write("dccert-block-marker")'`},
		{"BYP-0267", `env -i node -e 'require("fs").appendFileSync("disklink","dccert-block-marker")'`},
		{"BYP-0268", `env -i /usr/local/bin/node -e 'require("fs").writeFileSync("disklink","dccert-block-marker")'`},
		{"BYP-0270", `env -i -- python3 -c 'open("disklink","a").write("dccert-block-marker")'`},
		{"BYP-0271", `env -i A=B python3 -c 'open("disklink","a").write("dccert-block-marker")'`},
		{"BYP-0292", `env --unset=UNUSED python3 -c 'open("disklink","a").write("dccert-block-marker")'`},
		{"BYP-0297", `env -v python3 -c 'open("disklink","a").write("dccert-block-marker")'`},
		{"BYP-0298", `env -i /usr/bin/python3 -c 'open("disklink","a").write("dccert-block-marker")'`},
		{"BYP-0301", `env --ignore-environment node -e 'require("fs").appendFileSync("disklink","dccert-block-marker")'`},
		{"BYP-0302", `env -i -- node -e 'require("fs").appendFileSync("disklink","dccert-block-marker")'`},
		{"BYP-0303", `env -i A=B node -e 'require("fs").appendFileSync("disklink","dccert-block-marker")'`},
		{"BYP-0307", `env --unset=UNUSED node -e 'require("fs").appendFileSync("disklink","dccert-block-marker")'`},
		{"BYP-0313", `env -v node -e 'require("fs").appendFileSync("disklink","dccert-block-marker")'`},
		{"BYP-0314", `env -i /usr/local/bin/node -e 'require("fs").appendFileSync("disklink","dccert-block-marker")'`},
		{"V-0364-X06", `env -- A=B python3 -c 'open("disklink","a").write("dccert-block-marker")'`},
	} {
		t.Run(tc.id, func(t *testing.T) {
			home := t.TempDir()
			cwd := filepath.Join(home, "proj")
			if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(cwd, 0700); err != nil {
				t.Fatal(err)
			}
			keys := filepath.Join(home, ".ssh", "authorized_keys")
			if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(cwd, "disklink")
			if err := os.Symlink(keys, alias); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			if got := LiteralWriteOperands(tc.command, cwd, home); !slices.Contains(got, alias) {
				t.Fatalf("literal write operands %q omit %q", got, alias)
			}
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": tc.command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[alias] != keys {
				t.Fatalf("resolved target %q, want %q (all=%v)", targets[alias], keys, targets)
			}
		})
	}
}

func TestR103B07EnvNullRowsDoNotLaunchUtility(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, tc := range []struct{ id, flag, command string }{
		{"BYP-0295", "-0", `env -0 python3 -c 'open("disklink","a").write("k")'`},
		{"BYP-0296", "--null", `env --null python3 -c 'open("disklink","a").write("k")'`},
		{"BYP-0311", "-0", `env -0 node -e 'require("fs").appendFileSync("disklink","k")'`},
		{"BYP-0312", "--null", `env --null node -e 'require("fs").appendFileSync("disklink","k")'`},
	} {
		t.Run(tc.id, func(t *testing.T) {
			if got := LiteralWriteOperands(tc.command, cwd, home); len(got) != 0 {
				t.Fatalf("non-executing env command has write operands %v", got)
			}
			_, words, ok := envCommandWords([]string{"env", tc.flag, "python3"}, cwd)
			if !ok || len(words) != 0 {
				t.Fatalf("env null command words=%v ok=%v", words, ok)
			}
		})
	}
}

func TestR103B07FG3CPB001DynamicCopyOption(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{`read X <<< "--target-directory=$HOME/.ssh"; cp "$X" authorized_keys`, true},
		{`cp "$F" out.txt`, false},
		{`for f in *.txt; do cp "$f" build/; done`, false},
		{`cp source authorized_keys`, false},
	} {
		if got := DynamicCopyProtectedBasename(tc.command, "/home/test"); got != tc.want {
			t.Fatalf("command=%q got=%v want=%v", tc.command, got, tc.want)
		}
	}
}

func TestR103B07RelativeLinkThroughLinkedDirectory(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("POSIX link traversal")
	}
	home := t.TempDir()
	c := filepath.Join(home, "c")
	if err := os.MkdirAll(filepath.Join(c, "real"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh", "d"), 0700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, folder, want string }{
		{"ISSUE-1173", filepath.Join(c, "real"), filepath.Join(c, "ok.txt")},
		{"GAP-1556", filepath.Join(home, ".ssh", "d"), keys},
	} {
		t.Run(tc.id, func(t *testing.T) {
			folder := filepath.Join(c, "b2")
			link := filepath.Join(c, "l2")
			_ = os.Remove(folder)
			_ = os.Remove(link)
			if err := os.Symlink(tc.folder, folder); err != nil {
				t.Fatal(err)
			}
			leaf := "ok.txt"
			if tc.id == "GAP-1556" {
				leaf = "authorized_keys"
			}
			if err := os.Symlink("b2/../"+leaf, link); err != nil {
				t.Fatal(err)
			}
			got, ok := ResolveWriteTarget(link)
			if !ok || got != tc.want {
				t.Fatalf("target=%q ok=%v, want %q", got, ok, tc.want)
			}
			t.Setenv("HOME", home)
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": c,
				"tool_input": map[string]string{"command": "echo hi >> l2"}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[link] != tc.want {
				t.Fatalf("resolved target=%q, want %q", targets[link], tc.want)
			}
		})
	}
}

func TestR103B07MulticallCopyDestination(t *testing.T) {
	cwd := "/work/project"
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"GAP-1560-busybox", []string{"busybox", "cp", "-r", "big", "copy"}, "/work/project/copy"},
		{"GAP-1560-toybox", []string{"toybox", "cp", "-r", "big", "copy"}, "/work/project/copy"},
		{"ordinary-cp", []string{"cp", "-r", "big", "copy"}, "/work/project/copy"},
		{"not-copy", []string{"busybox", "ln", "big", "copy"}, ""},
		{"malformed-copy", []string{"busybox", "cp", "-r", "big"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CopyDestination(tc.argv, cwd); got != tc.want {
				t.Fatalf("destination=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestR103B07LinkCreatingExtractorRows(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id, command, target string
		want                bool
	}{
		{"GAP-1550-git", "git clone https://example.invalid/repo.git out; echo k > out/report.txt", "out/report.txt", true},
		{"GAP-1550-rsync-remote", "rsync -a example.invalid:/src out; echo k > out/report.txt", "out/report.txt", true},
		{"GAP-1550-jar", "jar xf archive.jar; echo k > report.txt", "report.txt", true},
		{"GAP-1550-ditto", "ditto -x -k archive.zip out; echo k > out/report.txt", "out/report.txt", true},
		{"GAP-1550-git-status", "git status; echo k > report.txt", "report.txt", false},
		{"GAP-1550-jar-list", "jar tf archive.jar; echo k > report.txt", "report.txt", false},
		{"GAP-1550-rsync-local", "rsync -a src/ out; echo k > out/report.txt", "out/report.txt", false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			links := CommandLinks("Bash", tc.command, cwd, home)
			got := links.OpaqueTarget(filepath.Join(cwd, tc.target))
			if got != tc.want {
				t.Fatalf("opaque=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestR103B07SafeDynamicRedirectProof(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("POSIX redirects")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{"proj/build", "proj/out", ".ssh"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"fresh directory", `out=$(mktemp -d); echo ok > "$out/x"`, true},
		{"fresh file", `out=$(mktemp); echo ok > "$out"`, true},
		{"numeric date", `x=$(date +%s); echo ok > "build/$x.log"`, true},
		{"numeric random", `echo ok > "out/run-$RANDOM.log"`, true},
		{"extra link statement", `out=$(mktemp -d); ln -sf ~/.ssh/authorized_keys "$out/x"; echo ok > "$out/x"`, false},
		{"extra protected redirect", `out=$(mktemp -d); echo ok > "$out/x" >> ~/.ssh/authorized_keys`, false},
		{"arbitrary variable", `out="$HOME/.ssh"; echo ok > "$out/authorized_keys"`, false},
		{"numeric without directory", `echo ok > "$RANDOM.log"`, false},
		{"numeric directory escape", `echo ok > "out/../run-$RANDOM.log"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SafeDynamicRedirect(tc.command, cwd, home); got != tc.want {
				t.Fatalf("safe dynamic proof=%v, want %v", got, tc.want)
			}
		})
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "out", "run-1.log")); err != nil {
		t.Fatal(err)
	}
	if SafeDynamicRedirect(`echo ok > "out/run-$RANDOM.log"`, cwd, home) {
		t.Fatal("possible existing protected alias was treated as safe")
	}
}
