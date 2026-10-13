// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type shellValueKind uint8

func shellZeroIndex(index syntax.ArithmExpr) bool {
	word, ok := index.(*syntax.Word)
	return ok && word.Lit() == "0"
}

func shellScalarFirstWord(word *syntax.Word) (*syntax.Word, bool) {
	if word == nil {
		return nil, false
	}
	clone := *word
	clone.Parts = append([]syntax.WordPart(nil), word.Parts...)
	changed := false
	var copyParts func([]syntax.WordPart) []syntax.WordPart
	copyParts = func(parts []syntax.WordPart) []syntax.WordPart {
		result := append([]syntax.WordPart(nil), parts...)
		for i, part := range result {
			switch part := part.(type) {
			case *syntax.ParamExp:
				if part.Index != nil && shellZeroIndex(part.Index) {
					copy := *part
					copy.Index = nil
					result[i] = &copy
					changed = true
				}
			case *syntax.DblQuoted:
				copy := *part
				copy.Parts = copyParts(part.Parts)
				result[i] = &copy
			}
		}
		return result
	}
	clone.Parts = copyParts(clone.Parts)
	return &clone, changed
}

const (
	shellValueUnknown shellValueKind = iota
	shellValueExact
	shellValueTemp
	shellValueNumeric
)

// shellKnownAssignmentValue reads command substitutions whose output is
// determined by literal operands or belongs to a confined value domain.
func shellKnownAssignmentValue(word *syntax.Word, home, cwd string, vars shellVariables) (string, shellValueKind) {
	if word == nil || len(word.Parts) != 1 {
		return "", shellValueUnknown
	}
	part := word.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok {
		if len(quoted.Parts) != 1 {
			return "", shellValueUnknown
		}
		part = quoted.Parts[0]
	}
	sub, ok := part.(*syntax.CmdSubst)
	if !ok || len(sub.Stmts) != 1 {
		return "", shellValueUnknown
	}
	stmt := sub.Stmts[0]
	if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && binary.Op == syntax.OrStmt {
		left, leftOK := shellSimpleCallWords(binary.X, home, vars)
		right, rightOK := shellSimpleCallWords(binary.Y, home, vars)
		if leftOK && rightOK && len(left) == 3 && left[0] == "git" && left[1] == "rev-parse" &&
			left[2] == "--show-toplevel" && len(right) == 1 && right[0] == "pwd" {
			if top, ok := shellGitTop(cwd); ok {
				return top, shellValueExact
			}
		}
		return "", shellValueUnknown
	}
	words, ok := shellSimpleCallWords(stmt, home, vars)
	if !ok || len(words) == 0 {
		return "", shellValueUnknown
	}
	switch words[0] {
	case "echo":
		if len(words) > 1 && !strings.HasPrefix(words[1], "-") {
			return strings.Join(words[1:], " "), shellValueExact
		}
	case "printf":
		if len(words) >= 2 {
			if value, ok := shellPrintfValue(words[1], words[2:]); ok {
				return value, shellValueExact
			}
		}
	case "pwd":
		if len(words) == 1 && filepath.IsAbs(cwd) {
			return cwd, shellValueExact
		}
	case "basename":
		if len(words) == 2 {
			return filepath.Base(words[1]), shellValueExact
		}
	case "realpath":
		if len(words) == 2 && filepath.IsAbs(cwd) {
			if path, err := filepath.EvalSymlinks(OperandPath(words[1], cwd)); err == nil {
				return path, shellValueExact
			}
		}
	case "date":
		if len(words) == 2 && shellDateDigits(words[1]) {
			return "", shellValueNumeric
		}
	case "mktemp":
		if len(words) == 1 || len(words) == 2 && words[1] == "-d" {
			return "", shellValueTemp
		}
	}
	return "", shellValueUnknown
}

func shellSimpleCallWords(stmt *syntax.Stmt, home string, vars shellVariables) ([]string, bool) {
	if stmt == nil {
		return nil, false
	}
	for _, redirect := range stmt.Redirs {
		if redirect.N == nil || redirect.N.Value != "2" || redirect.Op != syntax.RdrOut ||
			redirect.Word == nil || redirect.Word.Lit() != "/dev/null" {
			return nil, false
		}
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 {
		return nil, false
	}
	words := make([]string, len(call.Args))
	for i, word := range call.Args {
		value, ok := staticShellWordWithVars(word, home, vars, shellVariablePoison{})
		if !ok {
			return nil, false
		}
		words[i] = value
	}
	return words, true
}

func shellDateDigits(format string) bool {
	if !strings.HasPrefix(format, "+") || len(format) < 3 {
		return false
	}
	for i := 1; i < len(format); i += 2 {
		if i+1 >= len(format) || format[i] != '%' || !strings.ContainsRune("YmdHs", rune(format[i+1])) {
			return false
		}
	}
	return true
}

func shellGitTop(cwd string) (string, bool) {
	if !filepath.IsAbs(cwd) || os.Getenv("GIT_DIR") != "" || os.Getenv("GIT_WORK_TREE") != "" {
		return "", false
	}
	for path := cwd; ; path = filepath.Dir(path) {
		if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
			return path, true
		}
		if parent := filepath.Dir(path); parent == path {
			return cwd, true
		}
	}
}

func shellCandidateReadInputs(file *syntax.File, home, cwd string, candidates *shellVariableCandidateSet) {
	if !filepath.IsAbs(cwd) {
		return
	}
	writtenAt := map[string]int{}
	unknownAt := len(file.Stmts)
	for index, stmt := range file.Stmts {
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
				if name, ok := StaticWord(redirect.Word, home); ok {
					path := OperandPath(name, cwd)
					if _, seen := writtenAt[path]; !seen {
						writtenAt[path] = index
					}
				} else if index < unknownAt {
					unknownAt = index
				}
			}
		}
	}
	for stmtIndex, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			continue
		}
		program, ok := StaticWord(call.Args[0], home)
		if !ok || program != "read" && program != "mapfile" && program != "readarray" {
			continue
		}
		names := shellReadTargets(call.Args[1:], home)
		if program != "read" {
			names = shellMapfileTargets(call.Args[1:], home)
		}
		if len(names) != 1 {
			continue
		}
		for _, redirect := range stmt.Redirs {
			var value string
			var known bool
			switch redirect.Op {
			case syntax.WordHdoc:
				value, known = StaticWord(redirect.Word, home)
			case syntax.Hdoc, syntax.DashHdoc:
				if redirect.Hdoc != nil {
					value, known = StaticWord(redirect.Hdoc, home)
				}
			case syntax.RdrIn:
				if name, ok := StaticWord(redirect.Word, home); ok {
					path := OperandPath(name, cwd)
					if first, written := writtenAt[path]; written && first < stmtIndex || unknownAt < stmtIndex {
						continue
					}
					if info, err := os.Stat(path); err == nil && info.Size() <= 4096 {
						if data, err := os.ReadFile(path); err == nil {
							value, known = string(data), true
						}
					}
				}
			}
			if !known {
				continue
			}
			value, _, _ = strings.Cut(value, "\n")
			if program == "read" {
				value = strings.TrimSpace(value)
			}
			if !strings.ContainsAny(value, "\x00\r\n") {
				candidates.add(names[0], value)
				delete(candidates.unknown, names[0])
			}
		}
	}
}

func shellMapfileTargets(args []*syntax.Word, home string) []string {
	words, ok := shellStaticWords(args, home)
	if !ok {
		return nil
	}
	for i := 0; i < len(words); i++ {
		word := words[i]
		if word == "--" {
			if i+1 < len(words) && shellIdentifier(words[i+1]) {
				return []string{words[i+1]}
			}
			break
		}
		if !strings.HasPrefix(word, "-") || word == "-" {
			if shellIdentifier(word) {
				return []string{word}
			}
			return nil
		}
		if len(word) == 2 && strings.ContainsRune("dnOsuCc", rune(word[1])) {
			i++
			if i >= len(words) {
				return nil
			}
		}
	}
	return []string{"MAPFILE"}
}

func shellWordTemplate(word *syntax.Word) (prefix, suffix, name string, ok bool) {
	if word == nil {
		return "", "", "", false
	}
	var visit func([]syntax.WordPart) bool
	visit = func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				if name == "" {
					prefix += part.Value
				} else {
					suffix += part.Value
				}
			case *syntax.SglQuoted:
				if name == "" {
					prefix += part.Value
				} else {
					suffix += part.Value
				}
			case *syntax.DblQuoted:
				if !visit(part.Parts) {
					return false
				}
			case *syntax.ParamExp:
				if name != "" || part.Param == nil || part.Exp != nil || part.Index != nil || part.Repl != nil || part.Slice != nil {
					return false
				}
				name = part.Param.Value
			default:
				return false
			}
		}
		return true
	}
	ok = visit(word.Parts) && name != ""
	return
}

func shellTempTargetSafe(word *syntax.Word, name string) bool {
	prefix, suffix, variable, ok := shellWordTemplate(word)
	if !ok || variable != name || prefix != "" {
		return false
	}
	if suffix == "" {
		return true
	}
	if !strings.HasPrefix(suffix, "/") || strings.ContainsAny(suffix, "*?[]$`") {
		return false
	}
	for _, part := range strings.Split(suffix, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

func shellNumericTargetSafe(word *syntax.Word, cwd, home string, candidates shellVariableCandidateSet) bool {
	prefix, suffix, name, ok := shellWordTemplate(word)
	if !ok || name != "RANDOM" && name != "$" && !candidates.safeNumeric[name] ||
		strings.ContainsAny(prefix+suffix, "*?[]$`") || strings.Contains(suffix, "/") {
		return false
	}
	path := OperandPath(prefix+"0"+suffix, cwd)
	directory := filepath.Dir(path)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false
	}
	basePrefix := prefix[strings.LastIndex(prefix, "/")+1:]
	protected := newProtectedFiles(home)
	for _, entry := range entries {
		candidate := entry.Name()
		if !strings.HasPrefix(candidate, basePrefix) || !strings.HasSuffix(candidate, suffix) {
			continue
		}
		middle := strings.TrimSuffix(strings.TrimPrefix(candidate, basePrefix), suffix)
		if middle == "" {
			continue
		}
		digits := true
		for _, char := range middle {
			if char < '0' || char > '9' {
				digits = false
				break
			}
		}
		if !digits {
			continue
		}
		resolved, ok := ResolveWriteTarget(filepath.Join(directory, candidate))
		if !ok {
			return false
		}
		physical, known := protected.target(resolved)
		if !known || protected.has(physical) {
			return false
		}
	}
	return !protected.has(path)
}
