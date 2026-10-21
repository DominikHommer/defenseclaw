// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var (
	literalOpenCall    = regexp.MustCompile(`\b(?:open|File\.open|fs\.openSync|os\.open)\s*\(`)
	literalWriteCall   = regexp.MustCompile(`\b(?:appendFileSync|writeFileSync|File\.write|File\.binwrite)\s*\(`)
	literalNodeStream  = regexp.MustCompile(`\brequire\s*\(\s*['"]fs['"]\s*\)\s*\.createWriteStream\s*\(`)
	literalPathWrite   = regexp.MustCompile(`\b(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.write_(?:text|bytes)\s*\(`)
	literalPathOpen    = regexp.MustCompile(`\b(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.open\s*\(\s*['"]([waxr][waxr+bt]*)['"]\s*\)`)
	literalPerlOpen    = regexp.MustCompile(`\bopen\s+(?:my\s+)?(?:\$?\w+)\s*,\s*['"](?:>>|>)['"]\s*,\s*['"]([^'"]+)['"]`)
	literalAwkRedirect = regexp.MustCompile(`(?:>>|>)\s*['"]([^'"]+)['"]`)
	literalCopyCall    = regexp.MustCompile(`\bshutil\.copyfile\s*\(`)
)

// LiteralWriteOperands lists fixed write paths inside a directly invoked
// interpreter, awk program, or sed in-place command. The shell and gateway
// call this same extractor before resolving each operand through links.
func LiteralWriteOperands(command, cwd, home string) (operands []string) {
	return literalWriteOperandsDepth(command, cwd, home, 0)
}

func literalWriteOperandsDepth(command, cwd, home string, depth int) (operands []string) {
	if depth > 4 {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	add := func(name string) {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return
		}
		if !filepath.IsAbs(name) && !filepath.IsAbs(cwd) {
			return
		}
		operands = append(operands, OperandPath(name, cwd))
	}
	boundName, boundValue := boundedProgramAssignment(file, home)
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, declaration := node.(*syntax.FuncDecl); declaration {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			var static bool
			words[i], static = StaticWord(arg, home)
			if i == 0 && !static && simpleShellParameter(arg) == boundName {
				words[i], static = boundValue, true
			}
			if !static {
				return true
			}
		}
		for _, name := range literalProgramOperands(words, stmt, cwd, home, depth, len(file.Stmts) == 1) {
			add(name)
		}
		return true
	})
	operands = append(operands, literalPipelineOperands(file, cwd, home, depth)...)
	operands = append(operands, literalGeneratedScriptOperands(file, cwd, home, depth)...)
	return operands
}

// SedReplacedOperands names sed -i operands whose directory entry is
// replaced, so a pre-existing link at that entry is not a target write.
func SedReplacedOperands(command, cwd, home string) map[string]bool {
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	replaced := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			var static bool
			words[i], static = StaticWord(arg, home)
			if !static {
				return true
			}
		}
		if (programBase(words[0]) == "sed" || programBase(words[0]) == "gsed") &&
			!sedFollowsInPlaceLinks(words) {
			for _, name := range sedInPlaceFiles(words) {
				if !filepath.IsAbs(name) {
					if !filepath.IsAbs(cwd) {
						continue
					}
					name = OperandPath(name, cwd)
				}
				parent, ok := ResolveWriteTarget(rawParent(name))
				if !ok {
					continue
				}
				entry := filepath.Join(parent, filepath.Base(name))
				protected := false
				for _, path := range ProtectedAuthorizedKeysPaths(home) {
					if samePathName(entry, path) {
						protected = true
						break
					}
				}
				if !protected {
					replaced[name] = true
				}
			}
		}
		return true
	})
	return replaced
}

func sedParentProtected(name, cwd, home string) bool {
	parent, ok := ResolveWriteTarget(rawParent(OperandPath(name, cwd)))
	if !ok {
		return true
	}
	entry := filepath.Join(parent, filepath.Base(name))
	for _, path := range ProtectedAuthorizedKeysPaths(home) {
		if samePathName(entry, path) {
			return true
		}
	}
	return false
}

func rawParent(path string) string {
	index := strings.LastIndexAny(path, `/\`)
	if index < 0 {
		return "."
	}
	if index == 0 {
		return path[:1]
	}
	return path[:index]
}

func sedFollowsInPlaceLinks(words []string) bool {
	for _, word := range words[1:] {
		if word == "--follow-symlinks" {
			return true
		}
	}
	return false
}

func sedInPlaceFiles(words []string) []string {
	inPlace, script := false, false
	var files []string
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "-i" || word == "--in-place" || strings.HasPrefix(word, "--in-place=") ||
			strings.HasPrefix(word, "-i") && len(word) > 2:
			inPlace = true
		case word == "-e" || word == "--expression":
			i++
			script = true
		case strings.HasPrefix(word, "-e") && len(word) > 2 || strings.HasPrefix(word, "--expression="):
			script = true
		case strings.HasPrefix(word, "-"):
			continue
		case !script:
			script = true
		default:
			files = append(files, word)
		}
	}
	if !inPlace {
		return nil
	}
	return files
}

func literalInterpreterWrites(code string) []string {
	if len(code) > 16<<10 {
		return nil
	}
	var paths []string
	for _, loc := range literalOpenCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0]) {
			continue
		}
		call, ok := literalBoundedCall(code, loc[1]-1)
		if !ok {
			continue
		}
		args := literalCallArgs(call)
		name := strings.TrimSpace(code[loc[0] : loc[1]-1])
		switch {
		case name == "os.open" && len(args) >= 2 && literalOSWriteFlags(args[1]):
			if path, ok := literalString(args[0]); ok {
				paths = append(paths, path)
			}
		case name == "open" && len(args) >= 3 && perlRedirectMode(args[1]):
			if mode, ok := literalString(args[1]); ok && (mode == ">" || mode == ">>") {
				if path, ok := literalString(args[2]); ok {
					paths = append(paths, path)
				}
			}
		case len(args) >= 1:
			modeArg := ""
			if len(args) >= 2 {
				modeArg = args[1]
			}
			for _, arg := range args[1:] {
				if strings.HasPrefix(strings.TrimSpace(arg), "mode=") {
					modeArg = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), "mode="))
				}
			}
			if mode, ok := literalString(modeArg); ok && literalWriteMode(mode) {
				if path, ok := literalString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, loc := range literalWriteCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0]) {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) > 0 {
				if path, ok := literalString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, loc := range literalNodeStream.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0]) {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) > 0 {
				if path, ok := literalString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, loc := range literalCopyCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0]) {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) == 2 {
				if path, ok := literalString(args[1]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, match := range literalPathWrite.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0]) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	for _, match := range literalPathOpen.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0]) &&
			(strings.HasPrefix(code[match[0]:match[1]], "pathlib.") ||
				strings.Contains(code[:match[0]], "from pathlib import Path")) &&
			validPythonWriteMode(code[match[4]:match[5]]) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	for _, match := range literalPerlOpen.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0]) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	return paths
}

func perlRedirectMode(arg string) bool {
	mode, ok := literalString(arg)
	return ok && (mode == ">" || mode == ">>")
}

func literalWriteMode(mode string) bool {
	return strings.ContainsAny(mode, "wax+") || mode == ">" || mode == ">>"
}

func validPythonWriteMode(mode string) bool {
	if mode == "" || !strings.ContainsRune("waxr", rune(mode[0])) {
		return false
	}
	plus, binary, text := 0, 0, 0
	for _, flag := range mode[1:] {
		switch flag {
		case '+':
			plus++
		case 'b':
			binary++
		case 't':
			text++
		default:
			return false
		}
	}
	return plus <= 1 && binary+text <= 1 && (mode[0] != 'r' || plus == 1)
}

func literalOSWriteFlags(flags string) bool {
	for _, flag := range []string{"O_WRONLY", "O_RDWR", "O_APPEND", "O_TRUNC", "O_CREAT"} {
		if strings.Contains(flags, flag) {
			return true
		}
	}
	return false
}

func literalString(arg string) (string, bool) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 2 || arg[0] != arg[len(arg)-1] || arg[0] != '\'' && arg[0] != '"' {
		return "", false
	}
	value := arg[1 : len(arg)-1]
	if strings.Contains(value, "\\") {
		return "", false
	}
	return value, true
}

func literalBoundedCall(code string, open int) (string, bool) {
	depth := 0
	var quote byte
	for i := open; i < len(code); i++ {
		c := code[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return code[open : i+1], true
			}
		}
	}
	return "", false
}

func literalCallArgs(call string) []string {
	open := strings.IndexByte(call, '(')
	if open < 0 || !strings.HasSuffix(call, ")") {
		return nil
	}
	var args []string
	start, depth := open+1, 0
	var quote byte
	for i := start; i < len(call)-1; i++ {
		c := call[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(call[start:i]))
				start = i + 1
			}
		}
	}
	return append(args, strings.TrimSpace(call[start:len(call)-1]))
}

func literalCodePosition(code string, position int) bool {
	var quote byte
	comment := false
	for i := 0; i < position; i++ {
		c := code[i]
		if comment {
			if c == '\n' {
				comment = false
			}
			continue
		}
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' {
			quote = c
		} else if c == '#' {
			comment = true
		}
	}
	return quote == 0 && !comment
}
