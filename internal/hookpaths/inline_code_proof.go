// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
	"strings"
)

var awkVariableOutput = regexp.MustCompile(`(?:>>|>)\s*([A-Za-z_][A-Za-z0-9_]*)`)
var awkLiteralAssignment = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']+)["']`)

func literalAwkVariableWrites(words []string, code string) []string {
	values := map[string]string{}
	for i := 0; i < len(words); i++ {
		assignment := ""
		switch {
		case words[i] == "-v" && i+1 < len(words):
			i++
			assignment = words[i]
		case strings.HasPrefix(words[i], "-v"):
			assignment = strings.TrimPrefix(words[i], "-v")
		}
		if name, value, ok := strings.Cut(assignment, "="); ok && name != "" {
			values[name] = value
		}
	}
	for _, match := range awkLiteralAssignment.FindAllStringSubmatch(code, -1) {
		values[match[1]] = match[2]
	}
	var paths []string
	for _, match := range awkVariableOutput.FindAllStringSubmatch(code, -1) {
		if value := values[match[1]]; value != "" {
			paths = append(paths, value)
		}
	}
	return paths
}

type inlineString struct {
	start, end int
	value      string
}

// inlineStrings keeps source positions so a literal can be checked against
// the call that receives it. Escaped quotes remain part of the same value.
func inlineStrings(code string) []inlineString {
	var values []inlineString
	for i := 0; i < len(code); i++ {
		quote := code[i]
		if quote != '\'' && quote != '"' {
			continue
		}
		start := i
		var value strings.Builder
		for i++; i < len(code); i++ {
			if code[i] == '\\' && i+1 < len(code) {
				i++
				value.WriteByte(code[i])
				continue
			}
			if code[i] == quote {
				values = append(values, inlineString{start, i + 1, value.String()})
				break
			}
			value.WriteByte(code[i])
		}
	}
	return values
}

func inlineProtectedPath(value, cwd string, protected protectedFiles) bool {
	check := func(name string) bool {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") || !filepath.IsAbs(cwd) {
			return false
		}
		name = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(name, ">>"), ">"), "+<")
		if name == "" {
			return false
		}
		path := OperandPath(name, cwd)
		resolved, ok := ResolveWriteTarget(path)
		return ok && protected.has(resolved)
	}
	if check(value) {
		return true
	}
	for _, item := range strings.FieldsFunc(value, func(r rune) bool {
		return strings.ContainsRune(" \t\n\"'(),;[]{}|<>=\\", r)
	}) {
		if check(item) {
			return true
		}
	}
	return false
}

func inlineReadCall(language, name string, args []string) bool {
	switch name {
	case "print", "console.log", "console.info", "console.error", "puts", "warn":
		return true
	case "open", "builtins.open", "__builtins__.open", "io.open", "io.FileIO", "pathlib.Path.open", "File.open":
		mode := ""
		if len(args) > 1 {
			mode = args[1]
		}
		for _, arg := range args {
			if value, ok := strings.CutPrefix(strings.ReplaceAll(arg, " ", ""), "mode="); ok {
				mode = value
			}
		}
		if mode == "" {
			return true
		}
		value, ok := literalString(mode)
		return ok && !literalWriteMode(value)
	case "os.open":
		if language != "python" || len(args) < 2 {
			return false
		}
		mode := strings.TrimSpace(args[1])
		return mode == "0" || mode == "os.O_RDONLY"
	case "fs.readFileSync", "fs.readFile", "fs.promises.readFile", "fs.statSync", "fs.stat":
		return language == "node"
	case "fs.open", "fs.openSync", "fs.promises.open":
		if language != "node" || len(args) < 2 {
			return false
		}
		mode := strings.TrimSpace(args[1])
		if mode == "0" || mode == "fs.constants.O_RDONLY" {
			return true
		}
		value, ok := literalString(mode)
		return ok && !strings.ContainsAny(value, "wax+")
	case "os.stat", "os.lstat", "pathlib.Path.read_text", "pathlib.Path.read_bytes":
		return language == "python"
	}
	return false
}

// A protected path supplied to an unrecognised inline operation has no
// complete command-text proof. Recognised reads and display calls are safe.
func inlineProtectedUseUnknown(language, code, cwd, home string) bool {
	if cwd == "" || home == "" {
		return false
	}
	if language == "node" {
		code = literalNodeRequire.ReplaceAllString(code, "fs")
	}
	_, aliases := literalWriterBindings(language, code)
	protected := newProtectedFiles(home)
	for _, literal := range inlineStrings(code) {
		if !inlineProtectedPath(literal.value, cwd, protected) {
			continue
		}
		name, args, size := "", []string(nil), len(code)+1
		for _, loc := range literalCallName.FindAllStringIndex(code, -1) {
			if loc[0] > literal.start || !literalCodePosition(code, loc[0]) {
				continue
			}
			call, ok := literalBoundedCall(code, loc[1]-1)
			end := loc[1] - 1 + len(call)
			if !ok || end < literal.end || end-loc[0] >= size {
				continue
			}
			size = end - loc[0]
			name = strings.TrimSpace(code[loc[0] : loc[1]-1])
			args = literalCallArgs(call)
		}
		if inlineReadCall(language, name, args) {
			continue
		}
		canonical := literalCanonicalName(name, aliases)
		dataArgument := false
		for _, rule := range literalWriterRules[language] {
			if rule.callee != canonical {
				continue
			}
			if path, ok := literalString(literalWriterArg(args, rule.pathArg, rule.pathKeyword)); ok && path != literal.value {
				dataArgument = true
			}
		}
		if dataArgument {
			continue
		}
		if len(args) > 1 && (name == "shutil.copyfile" || name == "shutil.copy" ||
			name == "shutil.copy2" || name == "shutil.copytree" ||
			name == "fs.copyFile" || name == "fs.copyFileSync" ||
			name == "File::Copy::copy" || name == "File::Copy::cp") {
			if source, ok := literalString(args[0]); ok && source == literal.value {
				continue
			}
		}
		if language == "perl" && (name == "copy" || name == "move" || name == "cp" || name == "mv") &&
			!strings.Contains(code, "use File::Copy") {
			continue
		}
		if name == "" {
			before := strings.TrimSpace(code[:literal.start])
			after := strings.TrimSpace(code[literal.end:])
			if strings.HasSuffix(before, "==") || strings.HasSuffix(before, "!=") ||
				strings.HasPrefix(after, "==") || strings.HasPrefix(after, "!=") {
				continue
			}
		}
		return true
	}
	return false
}

func literalInterpreterAnalysis(language, code, cwd, home string) ([]string, bool) {
	paths, unknown := literalInterpreterWrites(language, code)
	return paths, unknown || inlineProtectedUseUnknown(language, code, cwd, home)
}
