// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestHandleAgentHook_StatementWithoutCommand(t *testing.T) {
	for _, failMode := range []string{"closed", "open"} {
		for _, prefix := range []struct{ name, source, separator string }{
			{"output", ">scratch", "; "},
			{"append", ">>scratch", "; "},
			{"quoted heredoc", "<<'EOF'\nbody\nEOF", "\n"},
			{"output and quoted heredoc", ">scratch <<'EOF'\nbody\nEOF", "\n"},
		} {
			for _, target := range []struct {
				name, command, action, rule string
			}{
				{"protected key read", "cat ~/.ssh/id_rsa", "block", "PATH-SSH-KEY"},
				{"root delete", "rm -rf /", "block", "CMD-RM-RF"},
				{"credential alert", "cat ~/.aws/credentials", "alert", "PATH-AWS-CREDS"},
			} {
				t.Run(failMode+"/"+prefix.name+"/"+target.name, func(t *testing.T) {
					store, logger := testStoreAndLogger(t)
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = "claudecode"
					cfg.Guardrail.HookFailMode = failMode
					cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
					api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
					plain := postDecisionForTest(t, &APIServer{scannerCfg: cfg}, "claudecode", "PreToolUse", target.command)
					response := postDecisionForTest(t, api, "claudecode", "PreToolUse", prefix.source+prefix.separator+target.command)
					if plain["action"] != target.action || response["action"] != target.action || response["mode"] != "action" {
						t.Fatalf("response=%v plain=%v, want %s/action", response, plain, target.action)
					}
					if target.action == "block" && !decisionIsDenied(response["claude_code_output"]) {
						t.Fatalf("output=%v, want a denial", response["claude_code_output"])
					}
					if !strings.Contains(strings.Join(responseStrings(response["findings"]), " "), target.rule) {
						t.Fatalf("findings=%v, want %s", response["findings"], target.rule)
					}
					row := soleHookDecisionForTest(t, store)
					if row.Structured["result"] != "ok" {
						t.Fatalf("audit result=%v, want ok", row.Structured["result"])
					}
				})
			}
		}
	}
}

func TestHandleAgentHook_BenignStatementWithoutCommand(t *testing.T) {
	for _, failMode := range []string{"closed", "open"} {
		t.Run(failMode, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.HookFailMode = failMode
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			response := postDecisionForTest(t, api, "claudecode", "PreToolUse", ">log; make")
			if response["action"] != "allow" || response["mode"] != "action" {
				t.Fatalf("response=%v, want normal allow", response)
			}
			row := soleHookDecisionForTest(t, store)
			if row.Structured["result"] != "ok" {
				t.Fatalf("audit result=%v, want ok", row.Structured["result"])
			}
		})
	}
}

func TestHandleAgentHook_StatementWithoutCommandObserve(t *testing.T) {
	for _, prefix := range []string{">scratch; ", "<<'EOF'\nbody\nEOF\n"} {
		for _, command := range []string{"cat ~/.ssh/id_rsa", "rm -rf /"} {
			t.Run(prefix+command, func(t *testing.T) {
				store, logger := testStoreAndLogger(t)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "observe"
				cfg.Guardrail.Connector = "claudecode"
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
				api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
				response := postDecisionForTest(t, api, "claudecode", "PreToolUse", prefix+command)
				if response["action"] != "allow" || response["mode"] != "observe" {
					t.Fatalf("response=%v, want observe allow", response)
				}
				row := soleHookDecisionForTest(t, store)
				if row.Structured["result"] != "ok" {
					t.Fatalf("audit result=%v, want ok", row.Structured["result"])
				}
			})
		}
	}
}

func responseStrings(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
