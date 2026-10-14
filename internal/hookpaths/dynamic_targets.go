// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type shellValueKind uint8

func shellHasLiteralGlob(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	for _, part := range word.Parts {
		if literal, ok := part.(*syntax.Lit); ok && strings.ContainsAny(literal.Value, "*?[") {
			return true
		}
	}
	return false
}

func shellRenameIntoGlob(file *syntax.File, redirect *syntax.Redirect, pattern, cwd, home string) bool {
	if file == nil || redirect == nil {
		return true
	}
	unsafe := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 || call.Pos().Offset() >= redirect.Pos().Offset() {
			return true
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for i, arg := range call.Args {
			words[i], static[i] = staticShellWordWithVars(arg, home, nil, shellVariablePoison{})
		}
		if !static[0] {
			return true
		}
		resolved := resolveLauncherWords(words, static, cwd)
		if !resolved.ok || resolved.noExec || len(resolved.words) == 0 || !resolved.static[0] {
			return true
		}
		program := programBase(resolved.words[0])
		if !slices.Contains(renamePrograms, program) {
			return true
		}
		if program == "rename" || len(resolved.words) < 3 {
			unsafe = true
			return false
		}
		for i, word := range resolved.words[1:] {
			if !resolved.static[i+1] || word == "-t" || word == "--target-directory" || strings.HasPrefix(word, "--target-directory=") {
				unsafe = true
				return false
			}
		}
		destination := finalOperandDestination(resolved.words[1:], resolved.cwd)
		matched, err := filepath.Match(pattern, destination)
		if destination == "" || err != nil || matched || destination == filepath.Dir(pattern) {
			unsafe = true
			return false
		}
		if info, statErr := os.Stat(destination); statErr == nil && info.IsDir() {
			parent, parentErr := filepath.EvalSymlinks(filepath.Dir(pattern))
			resolvedDestination, destinationErr := filepath.EvalSymlinks(destination)
			if parentErr != nil || destinationErr != nil || parent == resolvedDestination {
				unsafe = true
				return false
			}
		}
		return true
	})
	return unsafe
}

// shellLiteralGlobCandidates lists the current names of a redirect pattern.
// Earlier commands or expansions can change that set before the redirect runs.
func shellLiteralGlobCandidates(word *syntax.Word, cwd, home string, file *syntax.File, redirect *syntax.Redirect, links shellLinks) ([]string, bool) {
	if word == nil || len(word.Parts) != 1 || !filepath.IsAbs(cwd) || links.opaque || len(links.aliases) > 0 {
		return nil, false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	if !ok || !strings.ContainsAny(literal.Value, "*?[") || strings.HasPrefix(literal.Value, "~") ||
		strings.ContainsAny(literal.Value, "\x00\r\n") {
		return nil, false
	}
	pattern := OperandPath(literal.Value, cwd)
	if shellRenameIntoGlob(file, redirect, pattern, cwd, home) {
		return nil, false
	}
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) > 256 {
		return nil, false
	}
	if len(matches) == 0 {
		if _, err := os.Stat(filepath.Dir(pattern)); os.IsNotExist(err) {
			return nil, true
		}
		return []string{pattern}, true
	}
	return matches, true
}

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
	shellValueSlashless
	shellValueSafePath
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
		left, leftOK := shellSimpleCallWords(binary.X, home, cwd, vars)
		right, rightOK := shellSimpleCallWords(binary.Y, home, cwd, vars)
		if leftOK && rightOK && len(left) == 3 && left[0] == "git" && left[1] == "rev-parse" &&
			left[2] == "--show-toplevel" && len(right) == 1 && right[0] == "pwd" {
			if top, ok := shellGitTop(cwd); ok {
				return top, shellValueExact
			}
		}
		return "", shellValueUnknown
	}
	words, ok := shellSimpleCallWords(stmt, home, cwd, vars)
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
		if path, ok := shellPathReaderValue(words, cwd); ok {
			return path, shellValueExact
		}
	case "readlink":
		if path, ok := shellPathReaderValue(words, cwd); ok {
			return path, shellValueExact
		}
	case "date":
		if len(words) == 2 && shellDateDigits(words[1]) {
			return "", shellValueNumeric
		}
	case "mktemp":
		if shellMktempDirectorySafe(words, cwd, home) {
			return "", shellValueTemp
		}
	case "whoami":
		if len(words) == 1 {
			return "", shellValueSlashless
		}
	}
	return "", shellValueUnknown
}

// shellPathReaderValue evaluates literal path-reader operands using the same
// link resolution as write targets.
func shellPathReaderValue(words []string, cwd string) (string, bool) {
	if len(words) < 2 || !filepath.IsAbs(cwd) {
		return "", false
	}
	program := programBase(words[0])
	canonical, lexical := false, false
	relativeTo := ""
	var operand string
	for i := 1; i < len(words); i++ {
		word := words[i]
		if operand != "" {
			return "", false
		}
		switch {
		case word == "--":
			if i+1 != len(words)-1 {
				return "", false
			}
			operand = words[i+1]
		case program == "readlink" && (word == "-f" || word == "--canonicalize"):
			canonical = true
		case program == "readlink" && (word == "-e" || word == "--canonicalize-existing"):
			canonical = true
		case program == "readlink" && (word == "-m" || word == "--canonicalize-missing"):
			canonical = true
		case program == "realpath" && (word == "-s" || word == "--strip"):
			lexical = true
		case program == "realpath" && (word == "-e" || word == "--canonicalize-existing"):
		case program == "realpath" && (word == "-m" || word == "--canonicalize-missing"):
		case program == "realpath" && strings.HasPrefix(word, "--relative-to="):
			relativeTo = strings.TrimPrefix(word, "--relative-to=")
		case program == "realpath" && word == "--relative-to" && i+1 < len(words)-1:
			i++
			relativeTo = words[i]
		case strings.HasPrefix(word, "-"):
			return "", false
		default:
			operand = word
		}
	}
	if operand == "" {
		return "", false
	}
	path := OperandPath(operand, cwd)
	if _, err := os.Stat(path); err != nil {
		return "", false
	}
	if program == "readlink" && !canonical {
		value, err := os.Readlink(path)
		return value, err == nil
	}
	if lexical {
		path = filepath.Clean(path)
	} else {
		var ok bool
		path, ok = ResolveWriteTarget(path)
		if !ok {
			return "", false
		}
	}
	if relativeTo != "" {
		base, ok := ResolveWriteTarget(OperandPath(relativeTo, cwd))
		if !ok {
			return "", false
		}
		var err error
		path, err = filepath.Rel(base, path)
		if err != nil {
			return "", false
		}
	}
	return path, true
}

func shellMktempDirectorySafe(words []string, cwd, home string) bool {
	directory := os.TempDir()
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "-d" || word == "-u" || word == "--directory" || word == "--dry-run":
		case word == "-p" || word == "--tmpdir":
			i++
			if i >= len(words) {
				return false
			}
			directory = words[i]
		case strings.HasPrefix(word, "--tmpdir="):
			directory = strings.TrimPrefix(word, "--tmpdir=")
		default:
			return false
		}
	}
	directory = OperandPath(directory, cwd)
	resolved, ok := ResolveWriteTarget(directory)
	if !ok || !filepath.IsAbs(resolved) {
		return false
	}
	protectedDirectory := filepath.Join(home, ".ssh")
	return resolved != protectedDirectory && !strings.HasPrefix(resolved, protectedDirectory+string(filepath.Separator))
}

func shellBoundedTargetSafe(word *syntax.Word, home, cwd string, vars shellVariables) bool {
	if word == nil {
		return false
	}
	var prefix, suffix strings.Builder
	kind := shellValueUnknown
	seen := false
	var appendParts func([]syntax.WordPart) bool
	appendParts = func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			if sub, ok := part.(*syntax.CmdSubst); ok {
				if seen {
					return false
				}
				_, found := shellKnownAssignmentValue(&syntax.Word{Parts: []syntax.WordPart{sub}}, home, cwd, vars)
				if found != shellValueTemp && found != shellValueNumeric && found != shellValueSlashless {
					return false
				}
				kind, seen = found, true
				continue
			}
			if quoted, ok := part.(*syntax.DblQuoted); ok {
				if !appendParts(quoted.Parts) {
					return false
				}
				continue
			}
			piece, ok := shellStaticWordWithKnownCalls(&syntax.Word{Parts: []syntax.WordPart{part}}, home, cwd, vars, shellVariablePoison{})
			if !ok || strings.ContainsAny(piece, "*?[]\x00\r\n") {
				return false
			}
			if seen {
				suffix.WriteString(piece)
			} else {
				prefix.WriteString(piece)
			}
		}
		return true
	}
	if !appendParts(word.Parts) || !seen {
		return false
	}
	if kind == shellValueTemp {
		if prefix.Len() != 0 {
			return false
		}
		for _, part := range strings.Split(suffix.String(), "/") {
			if part == ".." {
				return false
			}
		}
		return suffix.Len() == 0 || strings.HasPrefix(suffix.String(), "/")
	}
	return shellPatternTargetSafe(prefix.String(), suffix.String(), cwd, home, kind == shellValueNumeric)
}

func shellStaticWordWithKnownCalls(word *syntax.Word, home, cwd string, vars shellVariables, poison shellVariablePoison) (string, bool) {
	if word != nil && strings.HasPrefix(word.Lit(), "~-") {
		return "", false
	}
	if value, ok := staticShellWordWithVars(word, home, vars, poison); ok {
		if strings.HasPrefix(value, "~-/") || value == "~-" {
			return "", false
		}
		return value, true
	}
	if word == nil {
		return "", false
	}
	known := vars.clone()
	if filepath.IsAbs(cwd) {
		known["PWD"] = cwd
	}
	var value strings.Builder
	var appendParts func([]syntax.WordPart, bool) bool
	appendParts = func(parts []syntax.WordPart, quoted bool) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				if strings.ContainsAny(part.Value, "*?[]") || !quoted && strings.ContainsAny(part.Value, " \t") {
					return false
				}
				value.WriteString(part.Value)
			case *syntax.SglQuoted:
				value.WriteString(part.Value)
			case *syntax.DblQuoted:
				if !appendParts(part.Parts, true) {
					return false
				}
			case *syntax.ParamExp:
				if part.Param != nil && part.Index != nil && part.Exp == nil && !poison.poisoned(part.Param.Value) {
					if index, ok := shellArrayIndex(part.Index); ok {
						if element, found := known[part.Param.Value+"["+index+"]"]; found {
							if strings.ContainsAny(element, "\x00\r\n") || !quoted && strings.ContainsAny(element, "*?[] \t") {
								return false
							}
							value.WriteString(element)
							continue
						}
					}
				}
				if part.Param != nil && len(part.Param.Value) == 1 && part.Param.Value[0] >= '1' && part.Param.Value[0] <= '9' {
					if positional, found := known[part.Param.Value]; found {
						if strings.ContainsAny(positional, "\x00\r\n") || !quoted && strings.ContainsAny(positional, "*?[] \t") {
							return false
						}
						value.WriteString(positional)
						continue
					}
				}
				piece, ok := staticShellWordWithVars(&syntax.Word{Parts: []syntax.WordPart{part}}, home, known, poison)
				if !ok || !quoted && strings.ContainsAny(piece, " \t") {
					return false
				}
				value.WriteString(piece)
			case *syntax.CmdSubst:
				piece, kind := shellKnownAssignmentValue(&syntax.Word{Parts: []syntax.WordPart{part}}, home, cwd, known)
				if kind != shellValueExact || strings.ContainsAny(piece, "*?[]\x00\r\n") ||
					!quoted && strings.ContainsAny(piece, " \t") {
					return false
				}
				value.WriteString(piece)
			default:
				return false
			}
		}
		return true
	}
	if !appendParts(word.Parts, false) || strings.ContainsAny(value.String(), "\x00\r\n") {
		return "", false
	}
	if strings.HasPrefix(value.String(), "~-/") || value.String() == "~-" {
		return "", false
	}
	return value.String(), true
}

func shellSimpleCallWords(stmt *syntax.Stmt, home, cwd string, vars shellVariables) ([]string, bool) {
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
		value, ok := shellStaticWordWithKnownCalls(word, home, cwd, vars, shellVariablePoison{})
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
				if script, supplied, static := shellProcessScript(redirect.Word, "", home); supplied {
					value, known = script, static
					break
				}
				if name, ok := StaticWord(redirect.Word, home); ok {
					path := OperandPath(name, cwd)
					if first, written := writtenAt[path]; written && first < stmtIndex || unknownAt < stmtIndex {
						continue
					}
					if data, ok := readRegularCommandFile(path, 4096); ok {
						value, known = string(data), true
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
	return shellPatternTargetSafe(prefix, suffix, cwd, home, true)
}

func shellPatternTargetSafe(prefix, suffix, cwd, home string, numeric bool) bool {
	if strings.ContainsAny(prefix+suffix, "*?[]$`\x00\r\n") || strings.Contains(suffix, "/") {
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
		if middle == "" || middle == "." || middle == ".." {
			continue
		}
		if numeric {
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
