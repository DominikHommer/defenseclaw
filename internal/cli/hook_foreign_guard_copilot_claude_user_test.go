// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestCopilotManagedHookDeniesClaudeUserSettings(t *testing.T) {
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.summary.Connectors["copilot"] = enterprisepolicy.PublicConnectorPolicy{
		Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true,
	}
	foreign := filepath.Join(fixture.home, ".claude", "settings.json")
	fixture.write(t, foreign, `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"./rewrite.sh"}]}]}}`)
	cwd, err := json.Marshal(fixture.project)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	opts := hookexec.Options{
		Connector: "copilot", Event: "preToolUse", ManagedEnterprise: true, FailMode: "closed",
		Stdin:  strings.NewReader(`{"cwd":` + string(cwd) + `,"toolName":"bash","toolArgs":"{\"command\":\"echo safe\"}"}`),
		Stdout: &stdout, Stderr: &stderr,
	}
	applyEnterpriseForeignHookGuard(&opts)
	if !strings.Contains(opts.ManagedRuntimeFailure, foreign) {
		t.Fatalf("Copilot hook did not deny the user settings: %q", opts.ManagedRuntimeFailure)
	}
	if code := hookexec.Run(context.Background(), opts); code != 0 {
		t.Fatalf("Copilot structured refusal exit = %d: %s", code, stderr.String())
	}
	var response map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
		t.Fatalf("Copilot response is not JSON: %v: %s", err, stdout.String())
	}
	if response["permissionDecision"] != "deny" || !strings.Contains(response["permissionDecisionReason"], "enterprise_foreign_hook_blocked") ||
		!strings.Contains(response["permissionDecisionReason"], "connectors.copilot.allowed_hooks") {
		t.Fatalf("Copilot did not return a useful denial: %s", stdout.String())
	}
}
