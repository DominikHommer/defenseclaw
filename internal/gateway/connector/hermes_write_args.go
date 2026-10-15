// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"regexp"
	"strings"
)

// HermesUnverifiedPatchArgs is the projection of a Hermes patch call whose
// write targets cannot be read: an apply_patch call with no envelope and no
// path, which the trusted-action parser treats as a patch whose targets are
// unknown (the protected files may be among them).
var HermesUnverifiedPatchArgs = json.RawMessage(`{}`)

// HermesTrustedWriteArgs projects a Hermes native file-write call onto the
// reviewed tool contract the trusted-action parser judges, so its write
// targets reach the same file-write rules as the other connectors' native
// write tools. Unprojected, the patch tool was an unknown tool and the
// write_file tool's cross_profile flag an unknown key, so neither call named
// a write target and a protected file such as ~/.ssh/authorized_keys was
// written with no rule (GAP-0667).
//
// The contract is Hermes' own (tools/file_tools.py in hermes-agent: the
// published PATCH_SCHEMA and WRITE_FILE_SCHEMA and the _handle_patch and
// _handle_write_file handlers, which read only the keys below and ignore
// any other):
//
//   - write_file {path, content, cross_profile} writes content to path; it
//     is judged as write_file {path, content}.
//   - patch {mode, path, old_string, new_string, replace_all, patch,
//     cross_profile}: mode defaults to "replace", which edits path and is
//     judged as Claude Code's edit {file_path, old_string, new_string,
//     replace_all}; mode "patch" applies a V4A patch whose Update, Add,
//     Delete and Move File headers name the files, judged as an apply_patch
//     envelope that names the same files (path, when given, is one of them:
//     Hermes checks and locks it as a target).
//
// A patch call that does not fit that contract (another mode, a key of the
// wrong type, a V4A patch Hermes cannot parse or that names no file) is
// projected onto HermesUnverifiedPatchArgs. A write_file call that does not
// fit is left alone: Hermes refuses it before it writes.
func HermesTrustedWriteArgs(toolName string, args json.RawMessage) (tool string, projected json.RawMessage, ok bool) {
	switch strings.TrimSpace(toolName) {
	case "write_file":
		out, ok := hermesWriteFileArgs(args)
		return "write_file", out, ok
	case "patch":
		if tool, out, ok := hermesPatchArgs(args); ok {
			return tool, out, true
		}
		return "apply_patch", HermesUnverifiedPatchArgs, true
	default:
		return "", args, false
	}
}

func hermesWriteFileArgs(args json.RawMessage) (json.RawMessage, bool) {
	fields, ok := hermesWriteFields(args)
	if !ok {
		return args, false
	}
	path, pathOK := hermesString(fields, "path")
	content, contentOK := hermesString(fields, "content")
	if !pathOK || path == "" || !contentOK {
		return args, false
	}
	out, err := json.Marshal(map[string]string{"path": path, "content": content})
	if err != nil {
		return args, false
	}
	return out, true
}

func hermesPatchArgs(args json.RawMessage) (string, json.RawMessage, bool) {
	fields, ok := hermesWriteFields(args)
	if !ok {
		return "", nil, false
	}
	mode := "replace"
	if _, present := fields["mode"]; present {
		if mode, ok = hermesString(fields, "mode"); !ok {
			return "", nil, false
		}
	}
	path := ""
	if raw, present := fields["path"]; present && !hermesJSONNull(raw) {
		if json.Unmarshal(raw, &path) != nil {
			return "", nil, false
		}
	}
	switch mode {
	case "replace":
		oldText, oldOK := hermesString(fields, "old_string")
		newText, newOK := hermesString(fields, "new_string")
		if path == "" || !oldOK || !newOK {
			return "", nil, false
		}
		edit := map[string]any{"file_path": path, "old_string": oldText, "new_string": newText}
		if raw, present := fields["replace_all"]; present && !hermesJSONNull(raw) {
			var all bool
			if json.Unmarshal(raw, &all) != nil {
				return "", nil, false
			}
			edit["replace_all"] = all
		}
		out, err := json.Marshal(edit)
		if err != nil {
			return "", nil, false
		}
		return "edit", out, true
	case "patch":
		body, bodyOK := hermesString(fields, "patch")
		if !bodyOK || body == "" {
			return "", nil, false
		}
		targets, parsed := HermesV4ATargets(body)
		if !parsed {
			return "", nil, false
		}
		if path != "" {
			targets = append([]HermesPatchTarget{{Path: path, Write: true}}, targets...)
		}
		out, err := json.Marshal(map[string]string{"patch": hermesApplyPatchEnvelope(targets)})
		if err != nil {
			return "", nil, false
		}
		return "apply_patch", out, true
	default:
		return "", nil, false
	}
}

// hermesWriteFields decodes a tool argument object whose keys do not repeat
// (Hermes reads a repeated key's last value; the parser must not guess).
func hermesWriteFields(args json.RawMessage) (map[string]json.RawMessage, bool) {
	if antigravityValidateUniqueJSON(args) != nil {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

// hermesString reads a string argument; a missing key or JSON null (Python's
// None, which the handlers refuse) is not one.
func hermesString(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, present := fields[key]
	if !present || hermesJSONNull(raw) {
		return "", false
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return "", false
	}
	return text, true
}

func hermesJSONNull(raw json.RawMessage) bool { return strings.TrimSpace(string(raw)) == "null" }

// HermesPatchTarget is one file a Hermes V4A patch changes: written (Update,
// Add, a Move destination) or removed (Delete, a Move source).
type HermesPatchTarget struct {
	Path  string
	Write bool
}

// hermesSpace is Python's str whitespace (re's \s for a str pattern and
// str.strip), which the Hermes V4A markers and paths use.
const hermesSpace = `[\t\n\v\f\r\x1c-\x1f \x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`

// The Hermes V4A markers (tools/patch_parser.py), matched at the start of a
// line as Python's re.match does.
var (
	hermesV4ABegin = regexp.MustCompile(`^\*\*\*` + hermesSpace + `*Begin` + hermesSpace + `+Patch` + hermesSpace + `*$`)
	hermesV4AEnd   = regexp.MustCompile(`^\*\*\*` + hermesSpace + `*End` + hermesSpace + `+Patch` + hermesSpace + `*$`)
	hermesV4AOps   = []struct {
		re    *regexp.Regexp
		write bool
		move  bool
	}{
		{re: regexp.MustCompile(`^\*\*\*` + hermesSpace + `*Update` + hermesSpace + `+File:` + hermesSpace + `*(.+)`), write: true},
		{re: regexp.MustCompile(`^\*\*\*` + hermesSpace + `*Add` + hermesSpace + `+File:` + hermesSpace + `*(.+)`), write: true},
		{re: regexp.MustCompile(`^\*\*\*` + hermesSpace + `*Delete` + hermesSpace + `+File:` + hermesSpace + `*(.+)`)},
		{re: regexp.MustCompile(`^\*\*\*` + hermesSpace + `*Move` + hermesSpace + `+File:` + hermesSpace + `*(.+?)` +
			hermesSpace + `*->` + hermesSpace + `*(.+)`), move: true},
	}
)

func hermesStrip(text string) string {
	return strings.TrimFunc(text, func(r rune) bool {
		switch {
		case r == '\t', r == '\n', r == '\v', r == '\f', r == '\r', r >= 0x1c && r <= 0x1f, r == ' ',
			r == 0x85, r == 0xa0, r == 0x1680, r >= 0x2000 && r <= 0x200a, r == 0x2028, r == 0x2029,
			r == 0x202f, r == 0x205f, r == 0x3000:
			return true
		}
		return false
	})
}

// HermesV4ATargets lists the files a Hermes V4A patch changes, read as
// Hermes' parse_v4a_patch reads them: the lines after the last Begin marker
// before the first End marker (from the top without one) up to that End
// marker; an operation header starts its line; an Update needs a hunk line.
// parsed is false when Hermes would refuse the patch (an empty path, an
// Update without hunks, a Move without a destination, a ".." component,
// which _collect_v4a_header_paths rejects) or when it names no file.
func HermesV4ATargets(body string) (targets []HermesPatchTarget, parsed bool) {
	lines := strings.Split(body, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	start, end := -1, len(lines)
	for i, line := range lines {
		if hermesV4ABegin.MatchString(line) {
			start = i
		} else if hermesV4AEnd.MatchString(line) {
			end = i
			break
		}
	}
	update, hunk := false, false
	for _, line := range lines[start+1 : end] {
		matched := false
		for _, op := range hermesV4AOps {
			groups := op.re.FindStringSubmatch(line)
			if groups == nil {
				continue
			}
			if update && !hunk {
				return nil, false
			}
			matched, update, hunk = true, false, false
			source := hermesStrip(groups[1])
			if source == "" || hermesTraversal(source) {
				return nil, false
			}
			switch {
			case op.move:
				destination := hermesStrip(groups[2])
				if destination == "" || hermesTraversal(destination) {
					return nil, false
				}
				targets = append(targets, HermesPatchTarget{Path: source}, HermesPatchTarget{Path: destination, Write: true})
			default:
				targets = append(targets, HermesPatchTarget{Path: source, Write: op.write})
				update = op.re == hermesV4AOps[0].re
			}
			break
		}
		if !matched && update && line != "" && !strings.HasPrefix(line, `\`) {
			// A hunk header or any other line of an Update's hunk.
			hunk = hunk || !strings.HasPrefix(line, "@@")
		}
	}
	if update && !hunk || len(targets) == 0 {
		return nil, false
	}
	return targets, true
}

// hermesTraversal reports a ".." path component, under either separator.
func hermesTraversal(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}

// hermesApplyPatchEnvelope is an apply_patch envelope that names targets:
// each written file as an Update and each removed file as a Delete, once.
func hermesApplyPatchEnvelope(targets []HermesPatchTarget) string {
	write := make(map[string]bool, len(targets))
	order := make([]string, 0, len(targets))
	for _, target := range targets {
		if _, seen := write[target.Path]; !seen {
			order = append(order, target.Path)
		}
		write[target.Path] = write[target.Path] || target.Write
	}
	var envelope strings.Builder
	envelope.WriteString("*** Begin Patch\n")
	for _, path := range order {
		if write[path] {
			envelope.WriteString("*** Update File: " + path + "\n@@\n+\n")
		} else {
			envelope.WriteString("*** Delete File: " + path + "\n")
		}
	}
	envelope.WriteString("*** End Patch\n")
	return envelope.String()
}
