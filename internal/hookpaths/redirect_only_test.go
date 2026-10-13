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

func TestRedirectOnlyStatements(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(protected), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(protected, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(home, "disklink")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{">", ">>", "2>", "&>", "<>", ">|"} {
		for _, path := range []string{"disklink", "out/empty"} {
			t.Run(prefix+path, func(t *testing.T) {
				checkRedirectOnly(t, prefix+" "+path, home, path == "disklink")
			})
		}
	}
	for _, item := range []struct {
		command   string
		protected bool
	}{
		{"{ > disklink; }", true},
		{"( > out/empty )", false},
		{"> out/empty ; > disklink", true},
		{"true && > disklink", true},
		{"true && > out/empty", false},
	} {
		t.Run(item.command, func(t *testing.T) {
			checkRedirectOnly(t, item.command, home, item.protected)
		})
	}
}

func checkRedirectOnly(t *testing.T, command, home string, protected bool) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": home,
		"tool_input": map[string]any{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok {
		t.Fatalf("invalid resolved targets for %q", command)
	}
	if targets[TruncatedKey] != "" {
		t.Fatalf("incomplete resolved targets for %q", command)
	}
	want := filepath.Join(home, ".ssh", "authorized_keys")
	got := false
	for key, value := range targets {
		if strings.HasSuffix(key, "/disklink") && value == want {
			got = true
		}
	}
	if got != protected {
		t.Fatalf("%q: protected target = %v, want %v; targets = %v", command, got, protected, targets)
	}
}
