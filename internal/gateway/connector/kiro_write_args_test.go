// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"testing"
)

// TestKiroTrustedWriteArgs pins the projection of each reviewed Kiro write
// shape onto write_file or edit with the text it writes, the conservative
// projection of every other write-class call, and the passthrough of the
// shapes that were already judged (fs_write {path, content}, other tools).
func TestKiroTrustedWriteArgs(t *testing.T) {
	const p = "~/.ssh/authorized_keys"
	write := `{"content":"k","path":"~/.ssh/authorized_keys"}`
	edit := `{"file_path":"~/.ssh/authorized_keys","new_string":"b","old_string":"a"}`
	for _, tc := range []struct {
		name, tool, args, wantTool, wantArgs string
		wantOK                               bool
	}{
		{"cli create", "fs_write", `{"command":"create","path":"` + p + `","file_text":"k"}`, "write_file", write, true},
		{"cli create purpose", "fs_write", `{"command":"create","path":"` + p + `","file_text":"k","summary":"s","__tool_use_purpose":"u"}`, "write_file", write, true},
		{"cli create new_str fallback", "fs_write", `{"command":"create","path":"` + p + `","new_str":"k"}`, "write_file", write, true},
		{"cli create file_text wins", "fs_write", `{"command":"create","path":"` + p + `","file_text":"k","new_str":"other"}`, "write_file", write, true},
		{"cli create null text", "fs_write", `{"command":"create","path":"` + p + `","file_text":null,"new_str":"k"}`, "write_file", write, true},
		{"cli create empty", "fs_write", `{"command":"create","path":"` + p + `"}`, "write_file", `{"content":"","path":"~/.ssh/authorized_keys"}`, true},
		{"cli append", "fs_write", `{"command":"append","path":"` + p + `","new_str":"k"}`, "write_file", write, true},
		{"cli insert", "fs_write", `{"command":"insert","path":"` + p + `","insert_line":3,"new_str":"k"}`, "write_file", write, true},
		{"cli str_replace", "fs_write", `{"command":"str_replace","path":"` + p + `","old_str":"a","new_str":"b"}`, "edit", edit, true},
		{"ide fs_write", "fs_write", `{"path":"` + p + `","text":"k"}`, "write_file", write, true},
		{"ide fs_append", "fs_append", `{"path":"` + p + `","text":"k"}`, "write_file", write, true},
		{"str_replace camel", "str_replace", `{"path":"` + p + `","oldStr":"a","newStr":"b"}`, "edit", edit, true},
		{"str_replace snake", "str_replace", `{"path":"` + p + `","old_str":"a","new_str":"b","__tool_use_purpose":"u"}`, "edit", edit, true},
		{"fs_write content with note", "fs_write", `{"path":"` + p + `","content":"k","__tool_use_purpose":"u"}`, "write_file", write, true},

		{"unknown command", "fs_write", `{"command":"delete","path":"` + p + `"}`, "apply_patch", `{}`, true},
		{"unknown key", "fs_write", `{"command":"create","path":"` + p + `","file_text":"k","mode":"0600"}`, "apply_patch", `{}`, true},
		{"ide unknown key", "fs_append", `{"path":"` + p + `","text":"k","content":"x"}`, "apply_patch", `{}`, true},
		{"repeated key", "fs_write", `{"path":"notes.txt","path":"` + p + `","text":"k"}`, "apply_patch", `{}`, true},
		{"path not a string", "fs_write", `{"path":["` + p + `"],"text":"k"}`, "apply_patch", `{}`, true},
		{"empty path", "fs_append", `{"path":" ","text":"k"}`, "apply_patch", `{}`, true},
		{"text not a string", "fs_append", `{"path":"` + p + `","text":7}`, "apply_patch", `{}`, true},
		{"append no text", "fs_write", `{"command":"append","path":"` + p + `"}`, "apply_patch", `{}`, true},
		{"insert no line", "fs_write", `{"command":"insert","path":"` + p + `","new_str":"k"}`, "apply_patch", `{}`, true},
		{"str_replace no new", "str_replace", `{"path":"` + p + `","oldStr":"a"}`, "apply_patch", `{}`, true},
		{"str_replace mixed dialects", "str_replace", `{"path":"` + p + `","oldStr":"a","new_str":"b"}`, "apply_patch", `{}`, true},
		{"not an object", "fs_write", `"x"`, "apply_patch", `{}`, true},

		{"fs_write content passthrough", "fs_write", `{"path":"` + p + `","content":"k"}`, "", `{"path":"` + p + `","content":"k"}`, false},
		{"other tool", "execute_bash", `{"command":"ls"}`, "", `{"command":"ls"}`, false},
		{"fs_read", "fs_read", `{"path":"` + p + `"}`, "", `{"path":"` + p + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tool, out, ok := KiroTrustedWriteArgs(tc.tool, json.RawMessage(tc.args))
			if tool != tc.wantTool || ok != tc.wantOK || string(out) != tc.wantArgs {
				t.Fatalf("KiroTrustedWriteArgs(%s, %s) = %q, %s, %t; want %q, %s, %t",
					tc.tool, tc.args, tool, out, ok, tc.wantTool, tc.wantArgs, tc.wantOK)
			}
		})
	}
}
