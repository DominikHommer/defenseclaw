// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// Codex calls its Windows shell tool Bash. The same complete-argv rule that
// blocks Claude Code must block both PowerShell and cmd marker writes there.
func TestCodexWindowsActionBlocksCompleteArgvMarker(t *testing.T) {
	resetConnectorRuleCategories(t)
	const ruleID = "R102-OSS-MARKER-BLOCK"
	if err := ApplyRulePackOverrides(&guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version: 1, Category: "r102-oss-marker", Rules: []guardrail.RuleDefYAML{{
			ID: ruleID, ToolCallOnly: true,
			Pattern:    "dccert-block-marker",
			Expression: `f.commands.exists(c, c.argv_complete && "dccert-block-marker" in c.argv)`,
			Title:      "OSS smoke marker block", Severity: "CRITICAL", Confidence: 0.99,
		}},
	}}}); err != nil {
		t.Fatal(err)
	}
	previous := codexShellRunsPowerShell
	codexShellRunsPowerShell = true
	t.Cleanup(func() { codexShellRunsPowerShell = previous })

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	api := &APIServer{scannerCfg: cfg}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"PowerShell cmdlet", `Set-Content -Path codex-blocked-marker.txt -Value dccert-block-marker`, true},
		{"PowerShell wrapper", `powershell -NoProfile -Command "Set-Content -Path codex-blocked-marker.txt -Value dccert-block-marker"`, true},
		{"cmd wrapper", `cmd.exe /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd caret redirect", `cmd.exe /c echo dccert-block-marker ^> codex-blocked2.txt`, true},
		{"cmd quoted wrapper", `cmd.exe /c "echo dccert-block-marker > codex-blocked2.txt"`, true},
		{"cmd with AutoRun disabled", `cmd.exe /d /c "echo dccert-block-marker > codex-blocked2.txt"`, true},
		{"benign", `Set-Content -Path codex-action-allowed.txt -Value hi`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "Bash", CWD: t.TempDir(),
				ToolInput: map[string]interface{}{"command": tc.command},
			})
			if tc.blocked {
				if resp.Action != "block" || resp.RawAction != "block" || !strings.Contains(resp.Reason, ruleID) ||
					!strings.Contains(strings.ToLower(string(mustJSONMarshal(resp.CodexOutput))), "deny") {
					t.Fatalf("%s: action=%s raw=%s rules=%v output=%v reason=%s", tc.command, resp.Action, resp.RawAction, resp.RuleIDs, resp.CodexOutput, resp.Reason)
				}
			} else if resp.Action != "allow" || containsString(resp.RuleIDs, ruleID) {
				t.Fatalf("benign command: action=%s rules=%v reason=%s", resp.Action, resp.RuleIDs, resp.Reason)
			}
		})
	}
}

// The action dispatcher is shared by the Windows connector hook profiles.
// Each supported connector must retain the same enforceable exact-argv match;
// native hook capability and response shape are checked for Codex above.
func TestWindowsConnectorMarkerRuleUsesCompleteCMDWrapperArgv(t *testing.T) {
	resetConnectorRuleCategories(t)
	const ruleID = "R102-OSS-MARKER-BLOCK"
	if err := ApplyRulePackOverrides(&guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version: 1, Category: "r102-oss-marker", Rules: []guardrail.RuleDefYAML{{
			ID: ruleID, ToolCallOnly: true,
			Pattern:    "dccert-block-marker",
			Expression: `f.commands.exists(c, c.argv_complete && "dccert-block-marker" in c.argv)`,
			Title:      "OSS smoke marker block", Severity: "CRITICAL", Confidence: 0.99,
		}},
	}}}); err != nil {
		t.Fatal(err)
	}
	for _, connectorName := range []string{
		"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "omnigent", "opencode",
	} {
		t.Run(connectorName, func(t *testing.T) {
			command := `cmd.exe /c echo dccert-block-marker > marker.txt`
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "powershell", Command: command, DialectHint: actionfacts.DialectPowerShell},
				LegacyText: command, Connector: connectorName, EnforcementCapable: true,
			})
			match := findingWithID(findings, ruleID)
			if match == nil || !match.contributesToEnforcement() {
				t.Fatalf("marker rule was not enforceable for %s: %v", connectorName, FindingStrings(findings))
			}
		})
	}
}
