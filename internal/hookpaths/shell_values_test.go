// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestShellVariableWriteCandidates(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	rows := []struct {
		name, command, target string
		unknown               bool
	}{
		{"formatted value", `printf -v f '%s%s' disk link; echo ok >> "$f"`, "disklink", false},
		{"formatted prefix", `printf -v f 'disk%s' link; echo ok >> "$f"`, "disklink", false},
		{"formatted suffix", `printf -v f '%slink' disk; echo ok >> "$f"`, "disklink", false},
		{"loop prefix", `for f in link; do echo ok >> "disk$f"; done`, "disklink", false},
		{"loop infix", `for f in skli; do echo ok >> "di${f}nk"; done`, "disklink", false},
		{"loop ordinary", `for f in one two; do echo ok >> "out/$f.log"; done`, "out/one.log", false},
		{"computed value", `f=other; eval 'f=disklink'; echo ok >> "$f"`, "", true},
		{"input value", `read f <<< disklink; echo ok >> "$f"`, "disklink", false},
		{"conditional default", `f=other; if true; then unset f; fi; echo ok >> "${f:-disklink}"`, "", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, unknown := ShellDynamicWriteOperands(row.command, cwd, home)
			if unknown != row.unknown {
				t.Fatalf("unknown = %v, want %v; paths = %v", unknown, row.unknown, paths)
			}
			if row.target != "" && !slices.Contains(paths, filepath.Join(cwd, row.target)) {
				t.Fatalf("paths = %v, want %q", paths, row.target)
			}
		})
	}
}

func TestDynamicTargetDomains(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{"build", "logs", "out"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cwd, "report.txt"), []byte("report.txt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command, target string
		unknown               bool
	}{
		{"temporary directory", `out=$(mktemp -d); printf ok > "$out/report.txt"`, "", false},
		{"temporary file", `out=$(mktemp); printf ok > "$out"`, "", false},
		{"working directory", `d=$(pwd); echo ok > "$d/build/report.txt"`, "build/report.txt", false},
		{"working directory variable", `out="$PWD"; echo ok > "$out/v1.txt"`, "v1.txt", false},
		{"basename", `n=$(basename "$PWD"); echo ok > "logs/$n.log"`, "logs/proj.log", false},
		{"numeric command", `x=$(date +%s); echo ok > "build/$x.log"`, "", false},
		{"numeric parameter", `echo ok > "out/run-$RANDOM.log"`, "", false},
		{"read literal", `read f <<< report.txt; echo ok > "out/$f"`, "out/report.txt", false},
		{"read file", `read f < report.txt; echo ok > "out/$f"`, "out/report.txt", false},
		{"read first element", `mapfile -t files <<< report.txt; echo ok > "out/${files[0]}"`, "out/report.txt", false},
		{"literal producer", `name=$(printf result); echo ok > "build/${name}.txt"`, "build/result.txt", false},
		{"resolved directory", `p=$(realpath build); echo ok > "$p/result.txt"`, "build/result.txt", false},
		{"unknown input", `read f < missing.txt; echo ok > "$f"`, "", true},
		{"temporary parent", `out=$(mktemp -d); echo ok > "$out/../authorized_keys"`, "", true},
		{"numeric linked member", `x=$(date +%s); ln -s ~/.ssh/authorized_keys "out/run-$x.log"; echo ok > "out/run-$x.log"`, "", true},
		{"updated input", `printf "../disklink\n" > report.txt; read f < report.txt; echo ok > "out/$f"`, "", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			paths, unknown := ShellDynamicWriteOperands(row.command, cwd, home)
			if unknown != row.unknown {
				t.Fatalf("unknown = %v, want %v; paths = %v", unknown, row.unknown, paths)
			}
			if row.target != "" && !slices.Contains(paths, filepath.Join(cwd, row.target)) {
				t.Fatalf("paths = %v, want %q", paths, row.target)
			}
		})
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "out", "run-123.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`tee -a $(readlink -f disklink) < report.txt`,
		`cp report.txt $(readlink disklink)`,
		`cp report.txt $(realpath disklink)`,
	} {
		t.Run(command, func(t *testing.T) {
			var paths []string
			paths, _ = ShellDynamicWriteOperands(command, cwd, home)
			for _, item := range ShellExtraWriteOperands(command, cwd, home) {
				paths = append(paths, item.Path)
			}
			if !slices.Contains(paths, keys) {
				t.Fatalf("resolved target missing: %v", paths)
			}
		})
	}
	if _, unknown := ShellDynamicWriteOperands(`echo ok > "out/run-$RANDOM.log"`, cwd, home); !unknown {
		t.Fatal("numeric target with a linked member must stay unknown")
	}
}

func TestKnownHomeOperators(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, row := range []struct{ command, target string }{
		{`echo ok >> ${HOME:?}/proj/out/x`, "proj/out/x"},
		{`echo ok >> ${HOME:-/tmp}/proj/out/y`, "proj/out/y"},
		{`echo ok >> ${HOME:?}/.ssh/authorized_keys`, ".ssh/authorized_keys"},
	} {
		t.Run(row.command, func(t *testing.T) {
			paths, parsed, dynamic := ShellWriteOperands(row.command, cwd, home)
			if !parsed || dynamic || !slices.Contains(paths, filepath.Join(home, row.target)) {
				t.Fatalf("paths=%v parsed=%v dynamic=%v", paths, parsed, dynamic)
			}
		})
	}
}
