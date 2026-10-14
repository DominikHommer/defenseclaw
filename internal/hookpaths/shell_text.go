// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type shellWrittenScript struct {
	code  string
	known bool
}

func shellStartupScript(call *syntax.CallExpr, words []string, static []bool, cwd, home string,
	written map[string]shellWrittenScript) (string, bool, bool) {
	if call == nil || len(words) == 0 || !static[0] {
		return "", false, false
	}
	program := programBase(words[0])
	name := ""
	switch program {
	case "bash":
		name = "BASH_ENV"
	case "sh", "dash", "ksh", "zsh":
		name = "ENV"
	default:
		return "", false, false
	}
	for _, assign := range call.Assigns {
		if assign.Name == nil || assign.Name.Value != name || assign.Value == nil {
			continue
		}
		path, ok := StaticWord(assign.Value, home)
		if !ok || path == "" {
			return "", true, false
		}
		if script, exists := written[OperandPath(path, cwd)]; exists {
			return script.code, true, script.known
		}
		return "", true, false
	}
	return "", false, false
}

func recordShellScriptWrite(scripts map[string]shellWrittenScript, stmt *syntax.Stmt, source, cwd, home string) {
	if stmt == nil || len(stmt.Redirs) == 0 {
		return
	}
	code, known := literalProducerCode(stmt, source, home)
	for _, redirect := range stmt.Redirs {
		if redirect.Op != syntax.RdrOut && redirect.Op != syntax.ClbOut && redirect.Op != syntax.AppOut {
			continue
		}
		path, static := StaticWord(redirect.Word, home)
		if !static || path == "" {
			continue
		}
		key := OperandPath(path, cwd)
		if redirect.Op == syntax.AppOut {
			previous, present := scripts[key]
			if !present || !previous.known || !known {
				scripts[key] = shellWrittenScript{}
				continue
			}
			code = previous.code + code
		}
		scripts[key] = shellWrittenScript{code, known}
	}
}

func shellTextInput(stmt *syntax.Stmt, source, home string) (string, bool, bool) {
	if stmt == nil {
		return "", false, false
	}
	for _, redirect := range stmt.Redirs {
		switch redirect.Op {
		case syntax.WordHdoc:
			code, ok := StaticWord(redirect.Word, home)
			return code, true, ok
		case syntax.Hdoc, syntax.DashHdoc:
			code, ok := shellHereDocumentBody(redirect, source, home)
			return code, true, ok && !strings.ContainsAny(code, "$`")
		}
	}
	return "", false, false
}

func shellHereDocumentBody(redirect *syntax.Redirect, source, home string) (string, bool) {
	if redirect == nil || redirect.Hdoc == nil || redirect.Word == nil {
		return "", false
	}
	start, end := int(redirect.Hdoc.Pos().Offset()), int(redirect.Hdoc.End().Offset())
	if start < 0 || end > len(source) || end <= start {
		return "", false
	}
	delimiter, ok := StaticWord(redirect.Word, home)
	if !ok || delimiter == "" {
		return "", false
	}
	body := strings.TrimSuffix(source[start:end], "\n")
	if !strings.HasSuffix(body, delimiter) {
		return "", false
	}
	return strings.TrimSuffix(body, delimiter), true
}

func shellProcessScript(word *syntax.Word, source, home string) (string, bool, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false, false
	}
	part, ok := word.Parts[0].(*syntax.ProcSubst)
	if !ok {
		return "", false, false
	}
	if len(part.Stmts) != 1 {
		return "", true, false
	}
	code, known := literalProducerCode(part.Stmts[0], source, home)
	return code, true, known
}

// shellTextCallScript finds literal shell text supplied by a command's input
// or by an earlier write in the same command. A dynamic source is incomplete.
func shellTextCallScript(stmt *syntax.Stmt, words []string, static []bool, source, cwd, home string,
	written map[string]shellWrittenScript) (string, bool, bool) {
	if len(words) == 0 || !static[0] {
		return "", false, false
	}
	resolved := resolveLauncherWords(words, static, cwd)
	if resolved.ok && len(resolved.words) > 0 {
		words, static = resolved.words, resolved.static
	}
	program := programBase(words[0])
	shell := program == "bash" || program == "sh" || program == "dash" || program == "zsh" || program == "ksh"
	sourced := program == "source" || program == "."
	if program == "trap" && len(words) > 2 && words[1] != "-p" && words[1] != "-l" {
		return words[1], true, static[1]
	}
	if !(shell || sourced || strings.Contains(words[0], "/") && !strings.HasPrefix(words[0], "/")) && program != "make" {
		return "", false, false
	}
	if script, supplied, known := shellTextInput(stmt, source, home); supplied {
		if shell && literalReadsStdin(words) || sourced && len(words) > 1 &&
			(words[1] == "/dev/stdin" || words[1] == "-") {
			return script, true, known
		}
		if program == "make" && len(words) >= 3 && words[1] == "-f" && words[2] == "-" {
			var recipe []string
			for _, line := range strings.Split(script, "\n") {
				if strings.HasPrefix(line, "\t") {
					recipe = append(recipe, strings.TrimSpace(line))
				}
			}
			if len(recipe) > 0 {
				return strings.Join(recipe, "\n"), true, known
			}
			return "", true, false
		}
	}
	if stmt != nil && (shell && literalReadsStdin(words) || sourced && len(words) > 1 &&
		(words[1] == "/dev/stdin" || words[1] == "-")) {
		for _, redirect := range stmt.Redirs {
			if redirect.Op != syntax.RdrIn {
				continue
			}
			path, known := StaticWord(redirect.Word, home)
			if !known || path == "" {
				return "", true, false
			}
			path = OperandPath(path, cwd)
			if script, found := written[path]; found {
				return script.code, true, script.known
			}
			data, known := readRegularCommandFile(path, 64*1024)
			if !known {
				return "", true, false
			}
			return string(data), true, true
		}
	}
	if stmt != nil {
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && (shell || sourced) && len(call.Args) > 1 {
			if code, supplied, known := shellProcessScript(call.Args[1], source, home); supplied {
				return code, true, known
			}
		}
	}
	name := ""
	if shell || sourced {
		if len(words) < 2 || strings.HasPrefix(words[1], "-") || !static[1] {
			return "", false, false
		}
		name = words[1]
	} else if strings.Contains(words[0], "/") {
		name = words[0]
	}
	if name == "" {
		return "", false, false
	}
	if code, ok := written[OperandPath(name, cwd)]; ok {
		return code.code, true, code.known
	}
	return "", false, false
}
