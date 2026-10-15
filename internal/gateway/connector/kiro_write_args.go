// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"strings"
)

// KiroUnverifiedWriteArgs is the projection of a Kiro write-class tool call
// that fits none of the reviewed shapes below: it is judged as a patch whose
// write targets are unknown (the protected files may be among them), so a
// fail-closed hook gives the conservative block instead of a silent allow.
var KiroUnverifiedWriteArgs = json.RawMessage(`{}`)

// KiroTrustedWriteArgs projects a Kiro native file-write call onto the
// reviewed write contracts the trusted-action parser judges (write_file
// {path, content} and edit {file_path, old_string, new_string}), carrying
// the text the call writes as content, so its target reaches the same
// file-write rules as Claude Code's Write and Edit and content rules fire
// too. Unprojected, only fs_write {path, content} named a write target: the
// kiro-cli and IDE shapes below reached no write rule and a write of
// ~/.ssh/authorized_keys was allowed (GAP-0688).
//
// The shapes (keys outside them make the call unreviewed):
//
//   - kiro-cli fs_write (the Amazon Q Developer CLI fs_write tool schema that
//     kiro-cli inherits: command create|str_replace|insert|append, path,
//     file_text, old_str, new_str, insert_line, summary): create writes
//     file_text (new_str when file_text is absent, as the CLI does), append
//     and insert write new_str, str_replace is an edit of old_str to new_str.
//   - Kiro IDE / v3 agent fs_write {path, text} and fs_append {path, text}
//     (AWS Labs Kiro hook payload reference): text is the content written.
//   - str_replace {path, oldStr, newStr} (same reference), and the snake_case
//     {path, old_str, new_str} spelling: an edit.
//
// Every shape may carry Kiro's __tool_use_purpose note and a summary.
// fs_write {path, content} is already a reviewed write_file shape and is
// left alone (ok false); with a note it is projected as write_file too. Any other fs_write, fs_append or str_replace call (a repeated key,
// an unknown command or key, a value of the wrong type, an empty path) is
// projected onto apply_patch KiroUnverifiedWriteArgs.
func KiroTrustedWriteArgs(toolName string, args json.RawMessage) (tool string, projected json.RawMessage, ok bool) {
	name := strings.TrimSpace(toolName)
	switch name {
	case "fs_write", "fs_append", "str_replace":
	default:
		return "", args, false
	}
	fields, valid := hermesWriteFields(args)
	if valid && name == "fs_write" && len(fields) == 2 && fields["path"] != nil && fields["content"] != nil {
		return "", args, false
	}
	if valid {
		if tool, out, ok := kiroWriteView(name, fields); ok {
			return tool, out, true
		}
	}
	return "apply_patch", KiroUnverifiedWriteArgs, true
}

// kiroLabelKeys are notes Kiro adds to a tool call; they write nothing.
var kiroLabelKeys = []string{"__tool_use_purpose", "summary"}

func kiroWriteView(name string, fields map[string]json.RawMessage) (string, json.RawMessage, bool) {
	path, ok := hermesString(fields, "path")
	if !ok || strings.TrimSpace(path) == "" {
		return "", nil, false
	}
	for _, key := range kiroLabelKeys {
		if _, ok := kiroOptionalString(fields, key); !ok {
			return "", nil, false
		}
	}
	if _, cli := fields["command"]; cli && name == "fs_write" {
		command, ok := hermesString(fields, "command")
		if !ok {
			return "", nil, false
		}
		switch command {
		case "create":
			if !kiroOnlyKeys(fields, "command", "path", "file_text", "new_str") {
				return "", nil, false
			}
			text, textOK := kiroOptionalString(fields, "file_text")
			fallback, fallbackOK := kiroOptionalString(fields, "new_str")
			if !textOK || !fallbackOK {
				return "", nil, false
			}
			if _, present := fields["file_text"]; !present || hermesJSONNull(fields["file_text"]) {
				text = fallback
			}
			return kiroWriteFileView(path, text)
		case "append":
			if !kiroOnlyKeys(fields, "command", "path", "new_str") {
				return "", nil, false
			}
			return kiroRequiredWriteFileView(fields, path, "new_str")
		case "insert":
			if !kiroOnlyKeys(fields, "command", "path", "insert_line", "new_str") {
				return "", nil, false
			}
			var line uint64
			if raw, present := fields["insert_line"]; !present || json.Unmarshal(raw, &line) != nil {
				return "", nil, false
			}
			return kiroRequiredWriteFileView(fields, path, "new_str")
		case "str_replace":
			if !kiroOnlyKeys(fields, "command", "path", "old_str", "new_str") {
				return "", nil, false
			}
			return kiroEditView(fields, path, "old_str", "new_str")
		default:
			return "", nil, false
		}
	}
	switch name {
	case "fs_write", "fs_append":
		if kiroOnlyKeys(fields, "path", "text") {
			return kiroRequiredWriteFileView(fields, path, "text")
		}
		if name == "fs_write" && kiroOnlyKeys(fields, "path", "content") {
			return kiroRequiredWriteFileView(fields, path, "content")
		}
	case "str_replace":
		if kiroOnlyKeys(fields, "path", "oldStr", "newStr") {
			return kiroEditView(fields, path, "oldStr", "newStr")
		}
		if kiroOnlyKeys(fields, "path", "old_str", "new_str") {
			return kiroEditView(fields, path, "old_str", "new_str")
		}
	}
	return "", nil, false
}

func kiroRequiredWriteFileView(fields map[string]json.RawMessage, path, key string) (string, json.RawMessage, bool) {
	text, ok := hermesString(fields, key)
	if !ok {
		return "", nil, false
	}
	return kiroWriteFileView(path, text)
}

func kiroWriteFileView(path, content string) (string, json.RawMessage, bool) {
	out, err := json.Marshal(map[string]string{"path": path, "content": content})
	if err != nil {
		return "", nil, false
	}
	return "write_file", out, true
}

func kiroEditView(fields map[string]json.RawMessage, path, oldKey, newKey string) (string, json.RawMessage, bool) {
	oldText, oldOK := hermesString(fields, oldKey)
	newText, newOK := hermesString(fields, newKey)
	if !oldOK || !newOK {
		return "", nil, false
	}
	out, err := json.Marshal(map[string]string{"file_path": path, "old_string": oldText, "new_string": newText})
	if err != nil {
		return "", nil, false
	}
	return "edit", out, true
}

// kiroOnlyKeys reports whether every key of fields is one of keys or a Kiro
// label key. The views check that their required keys are present.
func kiroOnlyKeys(fields map[string]json.RawMessage, keys ...string) bool {
	for key := range fields {
		if !kiroListed(key, keys) && !kiroListed(key, kiroLabelKeys) {
			return false
		}
	}
	return true
}

func kiroListed(key string, keys []string) bool {
	for _, listed := range keys {
		if key == listed {
			return true
		}
	}
	return false
}

// kiroOptionalString reads an optional string argument: absent or JSON null
// is "", true; any other non-string value is not one.
func kiroOptionalString(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, present := fields[key]
	if !present || hermesJSONNull(raw) {
		return "", true
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return "", false
	}
	return text, true
}
