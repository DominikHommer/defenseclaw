// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package copilotargs

import "strings"

// SurfaceVSCodeLocal is the --hook-surface value of a Copilot hook command
// registered for the VS Code Local harness. The hook forwards it in the
// X-DefenseClaw-Hook-Dialect header.
const SurfaceVSCodeLocal = "vscode-local"

// cliHookLocalEvents is how the VS Code Local harness maps the events of a
// Copilot CLI-format hook file such as the per-user
// ~/.copilot/hooks/defenseclaw.json (HOOKS_BY_TARGET[Target.GitHubCopilot] in
// microsoft/vscode src/vs/workbench/contrib/chat/common/promptSyntax/hookTypes.ts).
// The harness then sends its own Local payload to that command
// (chatHookService.ts: hook_event_name, tool_name, tool_input), never the CLI's
// camelCase body: "Runtime payloads still use the Local schema."
var cliHookLocalEvents = map[string]string{
	"sessionStart":        "SessionStart",
	"userPromptSubmitted": "UserPromptSubmit",
	"preToolUse":          "PreToolUse",
	"postToolUse":         "PostToolUse",
	"agentStop":           "Stop",
	"subagentStop":        "SubagentStop",
}

// LocalDialect returns the event a Copilot hook body is judged as and
// whether the gateway reads it in the VS Code Local dialect (tool_name,
// tool_input) rather than the CLI dialect (toolName, toolArgs). surface is
// the hook command's --hook-surface value, boundEvent the event the command
// is bound to, hookEventName the body's hook_event_name, and cliFields
// whether the body carries a toolName or toolArgs other than null.
//
// A command of the vscode-local surface reads its bound event in the Local
// dialect. A CLI hook-file command does so only when the body names the
// Local event its bound event maps to and carries no CLI field (GAP-1903:
// the Local harness also runs the per-user CLI hook file). The gateway picks
// its Copilot profile with this function, and the hook-side write-target
// resolver (hookpaths.ResolveConnector) reads the body with it, so the
// evidence describes the fields the gateway judges.
func LocalDialect(surface, boundEvent, hookEventName string, cliFields bool) (string, bool) {
	boundEvent = strings.TrimSpace(boundEvent)
	if strings.TrimSpace(surface) == SurfaceVSCodeLocal {
		return boundEvent, true
	}
	if local, ok := cliHookLocalEvents[boundEvent]; ok && !cliFields && strings.TrimSpace(hookEventName) == local {
		return local, true
	}
	return boundEvent, false
}
