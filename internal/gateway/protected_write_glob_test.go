// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestProtectedWriteGlobDecisions(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(key), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "result"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(cwd, "out-key.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(cwd, "prior-key.txt")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		want          bool
	}{
		{"ordinary unmatched", `echo ok > report-*.txt`, false},
		{"linked match", `echo ok > out-*.txt`, true},
		{"protected match", `echo ok > ../.ssh/authorized_key*`, true},
		{"changed match set", `mv prior-key.txt result-key.txt; echo ok > result-*.txt`, true},
		{"changed directory match", `mv prior-key.txt result/; echo ok > result/prior-*.txt`, true},
	}
	for _, row := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "/per-user", true: "/managed"}[managed], func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				request := trustedActionRequest{Input: input, ProtectedHomeHook: managed}
				if managed {
					request.ResolvedWriteTargets = map[string]string{hookpaths.CWDKey: cwd}
				}
				if got := trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)); got != row.want {
					t.Fatalf("decision = %v, want %v", got, row.want)
				}
			})
		}
	}
}

func TestProtectedWriteMissingProjectGlob(t *testing.T) {
	const connector = "protected-write-glob-test"
	installToolCallCorpusProfileConnector(t, connector, "default")
	project := filepath.Join(t.TempDir(), "missing", "project")
	input := actionfacts.Input{
		Tool:       "shell",
		Command:    "groupmems -g sudo -a agent > out-*.txt",
		CWD:        project,
		ActiveHome: filepath.Join(t.TempDir(), "home"),
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:              input,
		LegacyText:         input.Command,
		Connector:          connector,
		EnforcementCapable: true,
	})
	if buildVerdict(findings, "tool_call").Action == guardrailActionBlock {
		var ids []string
		for _, finding := range findings {
			ids = append(ids, finding.RuleID)
		}
		t.Fatalf("ordinary project target blocked by %v", ids)
	}
}
