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
