// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

const (
	patchBeginMarker = "*** Begin Patch"
	patchEndMarker   = "*** End Patch"
)

// patchTargetDirectives name the files an apply_patch envelope writes.
// Delete File and the source of a move remove a file, which also changes the
// protected file, so they count as write targets too.
var patchTargetDirectives = []string{
	"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:",
}

// ApplyPatchWriteTargets lists the files that the apply_patch edits in one
// tool call write, as absolute, cleaned paths. Codex sends apply_patch as its
// own tool (the envelope in tool_input.command, or a path field), or as a
// shell command that carries the envelope in a heredoc, a here-string, a
// quoted argument, a bash -c / sh -c script or a PowerShell @' '@ string.
// The envelope lines appear verbatim in each of those texts, so the text is
// scanned for envelopes and not parsed as one shell dialect.
//
// ok is false when the call carries an apply_patch edit whose targets are
// unknown: an envelope without "*** End Patch", an unknown "***" header, an
// empty path, a path with an unexpanded variable, a relative path without an
// absolute cwd, or an apply_patch tool call with no envelope and no path. The
// caller must then treat the protected file as a possible target. There is
// no bound on the number of targets.
func ApplyPatchWriteTargets(tool string, args json.RawMessage, command, cwd, home string) (targets []string, ok bool) {
	var fields map[string]json.RawMessage
	if len(args) != 0 {
		_ = json.Unmarshal(args, &fields)
	}
	patchTool := isApplyPatchToolName(tool)
	texts := []string{command}
	keys := []string{"command", "cmd"}
	if patchTool {
		keys = append(keys, "patch", "patchText", "patch_text", "input")
	}
	for _, key := range keys {
		texts = append(texts, patchTextField(fields[key]))
	}
	found := false
	for _, text := range texts {
		if text == "" {
			continue
		}
		paths, envelopes, parsed := patchEnvelopePaths(text)
		if !parsed || envelopes == 0 && !patchTool && invokesApplyPatch(text) {
			return nil, false
		}
		found = found || envelopes > 0
		for _, path := range paths {
			resolved, known := patchTargetPaths(path, cwd, home)
			if !known {
				return nil, false
			}
			targets = append(targets, resolved...)
		}
	}
	if patchTool {
		for _, key := range []string{"path", "file_path", "filePath"} {
			var path string
			if json.Unmarshal(fields[key], &path) != nil || path == "" {
				continue
			}
			resolved, known := patchTargetPaths(path, cwd, home)
			if !known {
				return nil, false
			}
			targets = append(targets, resolved...)
			found = true
		}
		if !found {
			return nil, false
		}
	}
	return targets, true
}

func isApplyPatchToolName(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "apply_patch", "applypatch", "apply-patch":
		return true
	}
	return false
}

// patchTextField reads a string field, or an argv array (["apply_patch",
// "<envelope>"], ["bash", "-lc", "<script>"]) joined by newlines.
func patchTextField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var argv []string
	if json.Unmarshal(raw, &argv) == nil {
		return strings.Join(argv, "\n")
	}
	return ""
}

// patchEnvelopePaths returns the directive paths of every envelope in text.
// An envelope starts on a line that ends with "*** Begin Patch" (any prefix:
// "apply_patch '", "@'", a quote) and ends on a line that starts with
// "*** End Patch". Added and removed lines (+, -) are content. Any other
// "***" line inside an envelope must be a known directive or "*** End of
// File". A Begin marker followed by a directive on the same line is an
// envelope with escaped newlines (printf, echo -e, $'...'), which is unknown.
func patchEnvelopePaths(text string) (paths []string, envelopes int, ok bool) {
	inside := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if !inside {
			index := strings.Index(line, patchBeginMarker)
			if index < 0 {
				continue
			}
			rest := line[index+len(patchBeginMarker):]
			if rest == "" {
				inside = true
				envelopes++
				continue
			}
			for _, directive := range patchTargetDirectives {
				if strings.Contains(rest, directive) {
					return nil, envelopes, false
				}
			}
			continue
		}
		if strings.HasPrefix(line, patchEndMarker) {
			inside = false
			continue
		}
		raw = strings.TrimLeft(raw, "\t")
		if strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") || !strings.HasPrefix(line, "***") {
			continue
		}
		if line == "*** End of File" {
			continue
		}
		known := false
		for _, directive := range patchTargetDirectives {
			if strings.HasPrefix(line, directive) {
				path := strings.TrimSpace(line[len(directive):])
				if path == "" {
					return nil, envelopes, false
				}
				paths = append(paths, path)
				known = true
				break
			}
		}
		if !known {
			return nil, envelopes, false
		}
	}
	if inside {
		return nil, envelopes, false
	}
	return paths, envelopes, true
}

// invokesApplyPatch reports a shell text that runs apply_patch as a command
// (first word of a line or after ; & | ( { or $( ). Its patch then comes from
// a file or a pipe the hook cannot read.
func invokesApplyPatch(text string) bool {
	segments := strings.FieldsFunc(text, func(r rune) bool {
		return strings.ContainsRune("\n;&|(){}`", r)
	})
	for _, segment := range segments {
		fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(segment), "$"))
		if len(fields) != 0 && isApplyPatchToolName(strings.Trim(fields[0], `"'`)) {
			return true
		}
	}
	return false
}

// patchTargetPaths makes a directive path absolute. apply_patch does not
// expand ~ or variables, but a shell or PowerShell wrapper may, so a home
// form yields both the home path and the literal path under cwd.
func patchTargetPaths(path, cwd, home string) ([]string, bool) {
	if len(path) >= 2 && (path[0] == '"' || path[0] == '\'') && path[len(path)-1] == path[0] {
		path = path[1 : len(path)-1]
	}
	if path == "" || len(path) > MaxWriteTargetPathBytes {
		return nil, false
	}
	var paths []string
	literal := path
	if rest, homeForm := trimHomePrefix(path); homeForm {
		if !filepath.IsAbs(home) {
			return nil, false
		}
		paths = append(paths, filepath.Clean(filepath.Join(home, rest)))
	} else if strings.ContainsAny(path, "$`") {
		return nil, false
	}
	if !filepath.IsAbs(literal) {
		if !filepath.IsAbs(cwd) {
			return nil, false
		}
		literal = filepath.Join(cwd, literal)
	}
	return append(paths, filepath.Clean(literal)), true
}

// trimHomePrefix strips a leading home form: ~, $HOME, ${HOME}, $env:HOME,
// $env:USERPROFILE or %USERPROFILE%, alone or followed by a separator.
func trimHomePrefix(path string) (string, bool) {
	lower := strings.ToLower(path)
	for _, prefix := range []string{"~", "${home}", "$home", "$env:userprofile", "$env:home", "%userprofile%"} {
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		rest := path[len(prefix):]
		if rest == "" {
			return "", true
		}
		if rest[0] == '/' || rest[0] == '\\' {
			return strings.TrimLeft(rest, `/\`), true
		}
	}
	return "", false
}
