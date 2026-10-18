// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	for _, tc := range []struct{ id, command string }{
		{"FG3-HOLD2-N0003", `printf ok > "tmp/run-$(date +%s).log"`},
		{"FG3-HOLD2-N0017", `out=$(mktemp -d "$PWD/tmp/work.XXXXXX"); printf ok > "$out/entry.txt"`},
		{"HOLD5-N0022", `out=$(mktemp "$PWD/tmp/out.XXXXXX"); printf ok > "$out"`},
		{"FG3-HOLD2-N0021", `stamp=$(date +%s); printf ok > "tmp/run-$stamp.log"`},
		{"FG3-HOLD2-N0022", `printf ok > "tmp/run-$RANDOM.log"`},
	} {
		t.Run(tc.id, func(t *testing.T) {
			if !SafeDynamicRedirect(tc.command, cwd, home) {
				t.Fatal("expected safe dynamic proof")
			}
			payload, err := json.Marshal(map[string]any{
				"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": tc.command},
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
