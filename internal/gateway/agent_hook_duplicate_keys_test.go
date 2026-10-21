// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Duplicate keys, missing write targets, and unknown write aliases leave a
// Copilot tool call's target set unproven. Refuse the call before it can be
// judged as an empty or ordinary project write.
func TestAgentHookRefusesUnprovenCopilotWriteCalls(t *testing.T) {
	for _, row := range []struct {
		name, body string
		block      bool
	}{
		{"ordinary write", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":{"filePath":"notes.txt","content":"ok"}}`, false},
		{"duplicate tool name", `{"sessionId":"s","timestamp":1790483549431,"toolName":"view","toolName":"create_file","toolArgs":{"filePath":"notes.txt","content":"ok"}}`, true},
		{"duplicate argument object", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":{"filePath":"notes.txt","content":"ok"},"toolArgs":{"filePath":"notes.txt","content":"ok"}}`, true},
		{"duplicate nested target", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":{"filePath":"other.txt","filePath":"notes.txt","content":"ok"}}`, true},
		{"duplicate JSON string target", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":"{\"filePath\":\"other.txt\",\"filePath\":\"notes.txt\",\"content\":\"ok\"}"}`, true},
		{"missing write args", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file"}`, true},
		{"array write args", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":[]}`, true},
		{"missing target", `{"sessionId":"s","timestamp":1790483549431,"toolName":"create_file","toolArgs":{"content":"ok"}}`, true},
		{"malformed patch", `{"sessionId":"s","timestamp":1790483549431,"toolName":"apply_patch","toolArgs":"not a patch"}`, true},
		{"unknown write alias", `{"sessionId":"s","timestamp":1790483549431,"toolName":"createFile","toolArgs":{"filePath":"notes.txt","content":"ok"}}`, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(row.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			recorder := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(recorder, req)
			var verdict struct {
				Action   string   `json:"action"`
				Findings []string `json:"findings"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &verdict); err != nil {
				t.Fatalf("response is not a verdict: %v", err)
			}
			want := "allow"
			if row.block {
				want = "block"
			}
			if verdict.Action != want {
				t.Fatalf("action = %q, want %q; findings = %v", verdict.Action, want, verdict.Findings)
			}
			if row.block && !strings.Contains(recorder.Body.String(), "HOOK-TOOL-CALL-UNPARSED") {
				t.Fatalf("ambiguous call did not name its reason: %v", verdict.Findings)
			}
		})
	}
}
