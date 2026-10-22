// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermespath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0499: a HERMES_HOME the DefenseClaw hooks recorded the account's
// agents running with, or a HOME the Hermes hook ran with, names a Hermes
// home a check of the resolved one does not prove.
func TestVerifyAccountHomeFailsOnARecordedRedirect(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(OverrideAccountEnvironmentForTest(filepath.Join(root, "system")))
	home := filepath.Join(root, "alice")
	resolved := filepath.Dir(ConfigPathForUserHome(home))
	other := filepath.Join(home, "work-hermes")
	record := filepath.Join(home, ".defenseclaw", "foreign-hook-env.json")
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAccountHome(home, resolved); err != nil {
		t.Fatalf("no evidence: %v", err)
	}
	for _, tc := range []struct {
		name, record, want string
	}{
		{"another connector's HERMES_HOME", `{"v":1,"connectors":{"claudecode":[{"vars":{"HERMES_HOME":` + jsonString(other) + `}}]}}`, other},
		{"the Hermes hook's HERMES_HOME", `{"v":1,"connectors":{"hermes":[{"vars":{"HERMES_HOME":` + jsonString(other) + `}}]}}`, other},
		{"a record that does not parse", `{"v":1,`, "parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(record, []byte(tc.record), 0o600); err != nil {
				t.Fatal(err)
			}
			err := VerifyAccountHome(home, resolved)
			if err == nil || !strings.Contains(err.Error(), "HERMES_HOME unproven") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyAccountHome = %v, want unproven naming %q", err, tc.want)
			}
		})
	}
	if err := os.WriteFile(record, []byte(`{"v":1,"connectors":{"claudecode":[{"vars":{"HERMES_HOME":`+jsonString(resolved)+`}}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAccountHome(home, resolved); err != nil {
		t.Fatalf("a recorded HERMES_HOME that is the resolved home: %v", err)
	}
}

func jsonString(value string) string {
	return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"`
}
