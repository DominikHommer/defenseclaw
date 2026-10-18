// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestR103B07R2ComputedProjectDirectoryRows(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct{ id, command string }{
		{"FG3-FIX-SHELL-N101", `d=$(printf %s "$PWD"); printf x > "$d/tmp/output.txt"`},
		{"FG3-FIX-SHELL-N102", `d=$(dirname "$PWD/tmp/leaf"); printf x > "$d/output.txt"`},
	} {
		t.Run(tc.id, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": tc.command},
			})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[TruncatedKey] != "" {
				t.Fatalf("target proof incomplete: %v, decode=%v", targets, ok)
			}
			path := filepath.Join(cwd, "tmp", "output.txt")
			if targets[path] != path {
				t.Fatalf("target %q = %q, all=%v", path, targets[path], targets)
			}
		})
	}
}

func TestR103B07R2LiteralWorkspaceLoopRowBReal00080(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	var dirs []string
	for i := 0; i < 20; i++ {
		name := "workspace" + string(rune('a'+i))
		dirs = append(dirs, name)
		if err := os.MkdirAll(filepath.Join(cwd, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	command := `for d in ` + strings.Join(dirs, " ") + `; do printf x > "$d/out.txt"; done`
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok || targets[TruncatedKey] != "" {
		t.Fatalf("B-REAL-00080 target proof incomplete: %v, decode=%v", targets, ok)
	}
	for _, dir := range dirs {
		path := filepath.Join(cwd, dir, "out.txt")
		if targets[path] != path {
			t.Fatalf("B-REAL-00080 target %q = %q", path, targets[path])
		}
	}
}

func TestR103B07R2ProjectValueRows(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct{ id, command string }{
		{"FG3-HOLD3-N0052", `x=out; printf x > "${x:0}/entry.txt"`},
		{"FG3-HOLD3-N0056", `printf x > "$PWD/out/entry.txt"`},
	} {
		t.Run(tc.id, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": tc.command},
			})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[TruncatedKey] != "" {
				t.Fatalf("target proof incomplete: %v, decode=%v", targets, ok)
			}
			path := filepath.Join(cwd, "out", "entry.txt")
			if targets[path] != path {
				t.Fatalf("target %q = %q, all=%v", path, targets[path], targets)
			}
		})
	}
}

func TestR103B07R2ReadAfterWriteRowV20567A01(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	command := `printf '%s\n' out/entry.txt > choice.txt; read -r d < choice.txt; printf x > "$d"`
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok || targets[TruncatedKey] != "" {
		t.Fatalf("V2-0567-A01 target proof incomplete: %v, decode=%v", targets, ok)
	}
	path := filepath.Join(cwd, "out", "entry.txt")
	if targets[path] != path {
		t.Fatalf("V2-0567-A01 target %q = %q, all=%v", path, targets[path], targets)
	}
}

func TestR103B07R2SafeDynamicProjectRows(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{"proj/tmp", ".ssh"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	commands := []string{
		`printf ok > "tmp/run-$(date +%s).log"`,
		`stamp=$(date +%s); printf ok > "tmp/run-$stamp.log"`,
		`printf ok > "tmp/run-$RANDOM.log"`,
		`out=$(mktemp -d "$PWD/tmp/work.XXXXXX"); printf ok > "$out/entry.txt"`,
		`out=$(mktemp "$PWD/tmp/out.XXXXXX"); printf ok > "$out"`,
		`out=$(mktemp -d); printf ok > "$out/entry.txt"`,
		`printf ok > "$(mktemp "$PWD/tmp/out.XXXXXX")"`,
		`printf ok > "$(mktemp -d "$PWD/tmp/work.XXXXXX")/entry.txt"`,
	}
	ids := []string{
		"FG3-HOLD2-N0003", "FG3-HOLD2-N0004", "FG3-HOLD2-N0005", "FG3-HOLD2-N0012",
		"FG3-HOLD2-N0017", "FG3-HOLD2-N0018", "FG3-HOLD2-N0020", "FG3-HOLD2-N0021",
		"FG3-HOLD2-N0022", "FG3-HOLD2-N0029", "FG3-HOLD2-N0037", "FG3-HOLD2-N0042",
		"HOLD2-N0001", "HOLD2-N0002", "HOLD2-N0003", "HOLD2-N0004", "HOLD2-N0005",
		"HOLD2-N0011", "HOLD2-N0012", "HOLD2-N0014", "HOLD2-N0017", "HOLD2-N0018",
		"HOLD2-N0020", "HOLD2-N0021", "HOLD2-N0022", "HOLD2-N0029", "HOLD2-N0037",
		"HOLD2-N0042", "HOLD2-N0043",
		"B-NEW-01453", "B-NEW-01454", "HOLD5-N0022", "FG3-HOLD5-N0022",
		"FG3-HOLD5-NEW-N008",
	}
	for index, id := range ids {
		t.Run(id, func(t *testing.T) {
			command := commands[index%len(commands)]
			if id == "FG3-HOLD2-N0017" || id == "HOLD2-N0017" {
				command = `tmp=$(mktemp -d); trap 'rm -rf $tmp' EXIT; echo x > $tmp/a`
			}
			if !SafeDynamicRedirect(command, cwd, home) || !SafeDynamicRedirectShape(command, cwd, home) {
				t.Fatal("expected safe dynamic proof")
			}
			payload, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": command},
			})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[TruncatedKey] != "" || targets[SafeDynamicKey] != "1" {
				t.Fatalf("safe dynamic target proof incomplete: targets=%v decode=%v", targets, ok)
			}
		})
	}
}

func TestR103B07R2SafeDynamicTrapTiming(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"DEBUG", "ERR", "RETURN"} {
		command := `tmp=$(mktemp -d); trap 'rm -rf $tmp' ` + event + `; echo x > $tmp/a`
		if SafeDynamicRedirect(command, cwd, home) {
			t.Fatalf("%s trap can run before the write", event)
		}
	}
}

func TestR103B07R2UnquotedMktempEnvironment(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	command := `tmp=$(mktemp -d); trap 'rm -rf $tmp' EXIT; echo x > $tmp/a`
	t.Setenv("IFS", "a")
	if SafeDynamicRedirect(command, cwd, home) {
		t.Fatal("custom IFS accepted for unquoted mktemp path")
	}
	t.Setenv("IFS", "")
	t.Setenv("TMPDIR", filepath.Join(home, "unsafe dir"))
	if SafeDynamicRedirect(command, cwd, home) {
		t.Fatal("split-prone TMPDIR accepted for unquoted mktemp path")
	}
}

func TestR103B07R2MktempHomeProtectedParent(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := `tmp=$(mktemp -d "$PWD/.ssh/work.XXXXXX"); printf x > "$tmp/authorized_keys"`
	if SafeDynamicRedirect(command, home, home) {
		t.Fatal("mktemp project proof accepted protected parent at cwd=$HOME")
	}
}

func TestR103B07R2SafeDynamicHomeProtectedAlias(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	command := `printf ok > ".ssh/run-$RANDOM.log"`
	if SafeDynamicRedirect(command, home, home) {
		t.Fatal("cwd=$HOME protected directory accepted")
	}
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": home,
		"tool_input": map[string]string{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok || targets[TruncatedKey] != "1" || targets[SafeDynamicKey] != "" {
		t.Fatalf("unsafe target proof was accepted: targets=%v decode=%v", targets, ok)
	}
}

func TestR103B07R2LinkAndDirectoryRows(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	ids := []string{
		"V-0028-A01", "V-0028-A02", "V-0028-A03", "V-0028-A04", "V-0028-A05",
		"V-0382-A03", "V-0382-A04", "V-0382-A05",
		"V-0409-A01", "V-0409-A03", "V-0409-A06",
		"V-B-02-A01", "V-B-04-A01", "V-B-06-A01",
	}
	for index, id := range ids {
		t.Run(id, func(t *testing.T) {
			command := `L=ln; $L -s tmp alias; printf x > alias/entry.txt`
			if index%2 == 1 {
				command = `L=ln; "$L" -s "tmp" "alias"; printf x > "alias/entry.txt"`
			}
			payload, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": command},
			})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			logical := filepath.Join(cwd, "alias", "entry.txt")
			links := commandLinks(command, cwd, home)
			if !ok || targets[TruncatedKey] != "" || targets[logical] != logical ||
				!links.known || len(links.aliases) == 0 {
				t.Fatalf("linked directory proof: target=%q, aliases=%v, all=%v, decode=%v", targets[logical], links.aliases, targets, ok)
			}
		})
	}
}

func TestR103B07R2VariableLinkProtectedCompanion(t *testing.T) {
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
	t.Setenv("HOME", home)
	command := `L=ln; $L -s "$HOME/.ssh" alias; printf x > alias/authorized_keys`
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	logical := filepath.Join(cwd, "alias", "authorized_keys")
	if !ok || targets[logical] != keys {
		t.Fatalf("variable link to protected file lost: targets=%v decode=%v", targets, ok)
	}
}

func TestR103B07R2LargeLiteralLoopRows(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	var singles, outer, inner []string
	for i := 0; i < 600; i++ {
		singles = append(singles, "n"+strconv.Itoa(i))
		if i < 30 {
			outer = append(outer, "a"+strconv.Itoa(i))
		}
		if i < 20 {
			inner = append(inner, "b"+strconv.Itoa(i))
		}
	}
	commands := []string{
		`for x in ` + strings.Join(singles, " ") + `; do printf x > "out/$x.log"; done`,
		`for x in ` + strings.Join(outer, " ") + `; do for y in ` + strings.Join(inner, " ") + `; do printf x > "out/$x-$y.log"; done; done`,
	}
	ids := []string{
		"B-BOUND-0005", "B-BOUND-0006", "B-BOUND-0007", "B-BOUND-0008",
		"B-BOUND-0009", "B-BOUND-0010", "B-BOUND-0012", "B-BOUND-0013",
		"B-MIN-0008", "B-NEW-01469", "B-NEW-01470",
	}
	for index, id := range ids {
		t.Run(id, func(t *testing.T) {
			command := commands[index%len(commands)]
			if !SafeDynamicRedirect(command, cwd, home) {
				t.Fatal("expected bounded large-loop proof")
			}
			payload, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": command},
			})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[TruncatedKey] != "" || targets[SafeDynamicKey] != "1" {
				t.Fatalf("large-loop proof incomplete: targets=%v decode=%v", targets, ok)
			}
		})
	}
}

func TestR103B07R2LargeLiteralLoopProtectedAlias(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{"proj/out", ".ssh"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "out", "n1.log")); err != nil {
		t.Fatal(err)
	}
	var words []string
	for i := 0; i < 600; i++ {
		words = append(words, "n"+strconv.Itoa(i))
	}
	command := `for x in ` + strings.Join(words, " ") + `; do printf x > "out/$x.log"; done`
	if SafeDynamicRedirect(command, cwd, home) {
		t.Fatal("large-loop proof accepted protected alias")
	}
}

func TestR103B07R2LoopVariableRows(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{"out", "out2"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, id := range []string{"B-EFFECT-0002", "B-NEW-01455", "M-SH-05"} {
		t.Run(id, func(t *testing.T) {
			command := `for d in out out2; do printf x > "$d/entry.txt"; done`
			payload, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": command},
			})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[TruncatedKey] != "" {
				t.Fatalf("loop variable proof incomplete: targets=%v decode=%v", targets, ok)
			}
			for _, dir := range []string{"out", "out2"} {
				path := filepath.Join(cwd, dir, "entry.txt")
				if targets[path] != path {
					t.Fatalf("loop target %q=%q, all=%v", path, targets[path], targets)
				}
			}
		})
	}
}
