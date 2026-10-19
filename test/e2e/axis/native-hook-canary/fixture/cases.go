// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package fixture contains fixed synthetic requests, never executable commands.
package fixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

type Case struct {
	Name, Version, Event, Body, NativeSurface string
}

// Versions select existing schema fixtures. No vendor binary is represented.
var cases = []Case{
	{"amp", "0.0.1785334225", "tool.call", `{"hook_event_name":"tool.call","tool_name":"bash","tool_input":{"command":COMMAND},"toolUseID":"fixed-call"}`, "plugin-action"},
	{"antigravity", "1.2.12", "PreToolUse", `{"conversationId":"synthetic-session","stepIdx":1,"workspacePaths":["/work"],"toolCall":{"id":"fixed-call","name":"run_command","args":{"CommandLine":COMMAND,"Cwd":"/work"}}}`, "decision-deny"},
	{"claudecode", "2.1.292", "PreToolUse", `{"hook_event_name":"PreToolUse","session_id":"synthetic-session","tool_use_id":"fixed-call","tool_name":"Bash","tool_input":{"command":COMMAND},"cwd":"/work"}`, "exit2"},
	{"codex", "0.146.0", "PreToolUse", `{"hook_event_name":"PreToolUse","session_id":"synthetic-session","tool_use_id":"fixed-call","tool_name":"shell","tool_input":{"command":COMMAND},"cwd":"/work"}`, "exit2"},
	{"copilot", "1.0.88", "preToolUse", `{"sessionId":"synthetic-session","timestamp":1,"cwd":"/work","toolName":"bash","toolArgs":{"command":COMMAND}}`, "advisory-on-loss"},
	{"cursor", "2026.07.23-e383d2b", "beforeShellExecution", `{"hook_event_name":"beforeShellExecution","conversation_id":"synthetic-session","command":COMMAND,"cwd":"/work","cursor_version":"2026.07.23-e383d2b"}`, "permission-deny"},
	{"devin", "3000.4.25", "PreToolUse", `{"hook_event_name":"PreToolUse","session_id":"synthetic-session","tool_name":"exec","tool_input":{"command":COMMAND},"cwd":"/work"}`, "exit2"},
	{"hermes", "0.19.0", "pre_tool_call", `{"hook_event_name":"pre_tool_call","session_id":"synthetic-session","tool_name":"terminal","tool_input":{"command":COMMAND},"cwd":"/work","extra":{}}`, "advisory-on-loss"},
	{"kiro", "2.24.1", "PreToolUse", `{"hook_event_name":"PreToolUse","session_id":"synthetic-session","tool_name":"shell","tool_input":{"command":COMMAND},"cwd":"/work"}`, "exit2"},
	{"omnigent", "0.13.0", "PreToolUse", `{"hook_event_name":"PreToolUse","session_id":"synthetic-session","tool_name":"bash","tool_input":{"command":COMMAND},"cwd":"/work"}`, "raw-bridge-only"},
	{"opencode", "1.18.14", "tool.execute.before", `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":COMMAND},"arguments_authoritative":true,"callID":"fixed-call"}`, "plugin-deny"},
	{"openhands", "1.16.0", "PreToolUse", `{"event_type":"PreToolUse","session_id":"synthetic-session","tool_name":"terminal","tool_input":{"command":COMMAND},"working_dir":"/work","metadata":{}}`, "exit2"},
}

func Cases() []Case { return append([]Case(nil), cases...) }

func Lookup(name string) (Case, error) {
	for _, value := range cases {
		if value.Name == name {
			return value, nil
		}
	}
	return Case{}, errors.New("unlisted fixed hook schema")
}

func (value Case) Payload(phase byte) ([]byte, error) {
	command := "printf fixed-hook-canary"
	if phase == 'B' {
		command = "rm -rf /"
	} else if phase != 'A' && phase != 'L' {
		return nil, errors.New("unlisted fixed hook phase")
	}
	encoded, _ := json.Marshal(command)
	raw := []byte(strings.Replace(value.Body, "COMMAND", string(encoded), 1))
	raw = bytes.ReplaceAll(raw, []byte(`"fixed-call"`), []byte(`"fixed-call-`+string(phase)+`"`))
	if len(raw) > 8192 || !json.Valid(raw) {
		return nil, errors.New("invalid fixed hook schema")
	}
	return raw, nil
}

type Row struct {
	Phase  string `json:"phase"`
	Code   int    `json:"hook_code"`
	Stdout string `json:"hook_stdout"`
	Stderr string `json:"hook_stderr"`
}
