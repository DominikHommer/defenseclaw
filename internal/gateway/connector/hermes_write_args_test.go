// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestHermesTrustedWriteArgs pins the projection of Hermes' native write
// tools onto the reviewed write contracts (GAP-0667).
func TestHermesTrustedWriteArgs(t *testing.T) {
	const unverified = `{}`
	for _, test := range []struct {
		name, tool, args string
		wantTool, want   string
		wantOK           bool
	}{
		{name: "replace default mode", tool: "patch", args: `{"path":"a.txt","old_string":"x","new_string":"y"}`,
			wantTool: "edit", want: `{"file_path":"a.txt","new_string":"y","old_string":"x"}`, wantOK: true},
		{name: "replace mode, ignored keys", tool: "patch",
			args:     `{"mode":"replace","path":"a.txt","old_string":"x","new_string":"y","replace_all":true,"cross_profile":true,"patch":"*** Update File: b.txt","note":1}`,
			wantTool: "edit", want: `{"file_path":"a.txt","new_string":"y","old_string":"x","replace_all":true}`, wantOK: true},
		{name: "replace all null", tool: "patch", args: `{"path":"a.txt","old_string":"x","new_string":"y","replace_all":null}`,
			wantTool: "edit", want: `{"file_path":"a.txt","new_string":"y","old_string":"x"}`, wantOK: true},
		{name: "v4a", tool: "patch", args: `{"mode":"patch","patch":"*** Begin Patch\n*** Update File: a.txt\n@@\n x\n+y\n*** Delete File: b.txt\n*** End Patch"}`,
			wantTool: "apply_patch", want: `{"patch":"*** Begin Patch\n*** Update File: a.txt\n@@\n+\n*** Delete File: b.txt\n*** End Patch\n"}`, wantOK: true},
		{name: "v4a with path", tool: "patch", args: `{"mode":"patch","path":"c.txt","patch":"*** Add File: a.txt\n+y"}`,
			wantTool: "apply_patch", want: `{"patch":"*** Begin Patch\n*** Update File: c.txt\n@@\n+\n*** Update File: a.txt\n@@\n+\n*** End Patch\n"}`, wantOK: true},
		{name: "unknown mode", tool: "patch", args: `{"mode":"diff","path":"a.txt","old_string":"x","new_string":"y"}`, wantTool: "apply_patch", want: unverified, wantOK: true},
		{name: "null mode", tool: "patch", args: `{"mode":null,"path":"a.txt","old_string":"x","new_string":"y"}`, wantTool: "apply_patch", want: unverified, wantOK: true},
		{name: "null new string", tool: "patch", args: `{"path":"a.txt","old_string":"x","new_string":null}`, wantTool: "apply_patch", want: unverified, wantOK: true},
		{name: "path not a string", tool: "patch", args: `{"path":["a.txt"],"old_string":"x","new_string":"y"}`, wantTool: "apply_patch", want: unverified, wantOK: true},
		{name: "replace all not a bool", tool: "patch", args: `{"path":"a.txt","old_string":"x","new_string":"y","replace_all":"yes"}`, wantTool: "apply_patch", want: unverified, wantOK: true},
		{name: "repeated key", tool: "patch", args: `{"path":"a.txt","path":"b.txt","old_string":"x","new_string":"y"}`, wantTool: "apply_patch", want: unverified, wantOK: true},
		{name: "v4a unparsable", tool: "patch", args: `{"mode":"patch","patch":"rewrite a.txt please"}`, wantTool: "apply_patch", want: unverified, wantOK: true},
		{name: "not an object", tool: "patch", args: `"a.txt"`, wantTool: "apply_patch", want: unverified, wantOK: true},
		{name: "write_file", tool: "write_file", args: `{"path":"a.txt","content":"y","cross_profile":true}`,
			wantTool: "write_file", want: `{"content":"y","path":"a.txt"}`, wantOK: true},
		{name: "write_file refused by Hermes", tool: "write_file", args: `{"path":"a.txt"}`, wantTool: "write_file", want: `{"path":"a.txt"}`},
		{name: "other tool", tool: "terminal", args: `{"command":"ls"}`, want: `{"command":"ls"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			tool, got, ok := HermesTrustedWriteArgs(test.tool, json.RawMessage(test.args))
			if tool != test.wantTool || ok != test.wantOK || string(got) != test.want {
				t.Fatalf("got %q %s %t, want %q %s %t", tool, got, ok, test.wantTool, test.want, test.wantOK)
			}
		})
	}
}

// TestHermesV4ATargets pins the reading of a V4A patch as Hermes'
// parse_v4a_patch reads it.
func TestHermesV4ATargets(t *testing.T) {
	w := func(path string) HermesPatchTarget { return HermesPatchTarget{Path: path, Write: true} }
	d := func(path string) HermesPatchTarget { return HermesPatchTarget{Path: path} }
	for _, test := range []struct {
		name, body string
		want       []HermesPatchTarget
	}{
		{name: "update add delete", body: "*** Begin Patch\n*** Update File: a\n@@ f @@\n x\n+y\n*** Add File: /abs/b\n+z\n*** Delete File: ~/c\n*** End Patch\n",
			want: []HermesPatchTarget{w("a"), w("/abs/b"), d("~/c")}},
		{name: "move", body: "*** Move File: a.md  ->  ~/.ssh/authorized_keys\n", want: []HermesPatchTarget{d("a.md"), w("~/.ssh/authorized_keys")}},
		{name: "loose whitespace", body: "***Update \t File: ~/.ssh/authorized_keys \nctx line\n", want: []HermesPatchTarget{w("~/.ssh/authorized_keys")}},
		{name: "crlf", body: "*** Begin Patch\r\n*** Update File: a\r\n+y\r\n*** End Patch\r\n", want: []HermesPatchTarget{w("a")}},
		// Parsing starts after the last Begin line before the first End line.
		{name: "last begin", body: "*** Begin Patch\n*** Update File: a\n+y\n***  Begin  Patch\n*** Update File: b\n+y\n*** End Patch\n*** Update File: c\n+y\n",
			want: []HermesPatchTarget{w("b")}},
		{name: "content lines are not headers", body: "*** Update File: a\n+*** Update File: b\n *** Delete File: c\n", want: []HermesPatchTarget{w("a")}},
		{name: "update without hunk", body: "*** Update File: a\n@@ f @@\n*** Add File: b\n"},
		{name: "update only a no-newline marker", body: "*** Update File: a\n\\ No newline at end of file\n"},
		{name: "empty path", body: "*** Delete File:   \n"},
		{name: "move without destination", body: "*** Move File: a -> \n"},
		{name: "traversal", body: "*** Delete File: x/../../.ssh/authorized_keys\n"},
		{name: "no operations", body: "*** Begin Patch\n*** End Patch\n"},
		{name: "prose", body: "please update a\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, parsed := HermesV4ATargets(test.body)
			if parsed != (test.want != nil) || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %+v parsed=%t, want %+v", got, parsed, test.want)
			}
		})
	}
}
