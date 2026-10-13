// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var (
	literalAwkRedirect = regexp.MustCompile(`(?:>>|>)\s*['"]([^'"]+)['"]`)
)

// LiteralWriteOperands lists fixed write paths inside a directly invoked
// interpreter, awk program, or sed in-place command. The shell and gateway
// call this same extractor before resolving each operand through links.
func LiteralWriteOperands(command, cwd, home string) (operands []string) {
	operands, _ = LiteralWriteAnalysis(command, cwd, home)
	return operands
}

// LiteralWriteAnalysis also reports a write whose destination is not a
// literal path, so both hook and gateway can treat that decision as unknown.
func LiteralWriteAnalysis(command, cwd, home string) (operands []string, unknown bool) {
	contexts, _ := shellAnalysisScripts(command, cwd, home)
	add := func(name, base string) {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return
		}
		if !filepath.IsAbs(name) && !filepath.IsAbs(base) {
			return
		}
		operands = append(operands, OperandPath(name, base))
	}
	for _, context := range contexts {
		cwd := context.cwd
		states := shellWordStates(context.file, home, shellVariablePoison{})
		syntax.Walk(context.file, func(node syntax.Node) bool {
			if pipe, ok := node.(*syntax.BinaryCmd); ok && pipe.Op == syntax.Pipe {
				cmdCWD, language, code, ok := literalPipelineInterpreterInput(pipe, command, cwd, home)
				if ok {
					paths, dynamic := literalInterpreterWrites(language, code)
					unknown = unknown || dynamic
					for _, name := range paths {
						add(name, cmdCWD)
					}
				}
				return true
			}
			if stmt, ok := node.(*syntax.Stmt); ok {
				call, ok := stmt.Cmd.(*syntax.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				cmdCWD, programWords, ok := literalProgramWordsWithVars(call, cwd, home, states.varsFor(call.Args[0]))
				if !ok || len(programWords) == 0 {
					return true
				}
				program := programBase(programWords[0])
				language := literalLanguage(program)
				if language == "" || !literalReadsStdin(programWords) {
					return true
				}
				for _, redirect := range stmt.Redirs {
					if (redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc) || redirect.Hdoc == nil {
						continue
					}
					start, end := int(redirect.Hdoc.Pos().Offset()), int(redirect.Hdoc.End().Offset())
					if start < 0 || end > len(command) || end <= start {
						continue
					}
					paths, dynamic := literalInterpreterWrites(language, command[start:end])
					unknown = unknown || dynamic
					for _, name := range paths {
						add(name, cmdCWD)
					}
				}
				for _, redirect := range stmt.Redirs {
					if redirect.Op != syntax.WordHdoc || redirect.Word == nil {
						continue
					}
					code, static := staticShellWordWithVars(redirect.Word, home, nil, shellVariablePoison{})
					if !static {
						continue
					}
					paths, dynamic := literalInterpreterWrites(language, code)
					unknown = unknown || dynamic
					for _, name := range paths {
						add(name, cmdCWD)
					}
				}
				return true
			}
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if context.handled[int(call.Pos().Offset())] {
				return true
			}
			if _, static := StaticWord(call.Args[0], home); !static {
				paths, dynamic := literalUnresolvedProgramWrites(call.Args, home)
				unknown = unknown || dynamic
				for _, name := range paths {
					add(name, cwd)
				}
			}
			cmdCWD, programWords, ok := literalProgramWordsWithVars(call, cwd, home, states.varsFor(call.Args[0]))
			if !ok || len(programWords) == 0 {
				return true
			}
			program := programBase(programWords[0])
			switch {
			case literalInterpreterProgram(program):
				if code, ok := literalInterpreterCode(program, programWords); ok {
					paths, dynamic := literalInterpreterWrites(literalLanguage(program), code)
					unknown = unknown || dynamic
					for _, name := range paths {
						add(name, cmdCWD)
					}
				}
			case program == "awk" || program == "gawk" || program == "mawk" || program == "nawk":
				for _, arg := range programWords[1:] {
					if strings.Contains(arg, "{") {
						for _, match := range literalAwkRedirect.FindAllStringSubmatch(arg, -1) {
							add(match[1], cmdCWD)
						}
					}
				}
			case program == "sed" || program == "gsed":
				for _, name := range sedInPlaceFiles(programWords) {
					if sedFollowsInPlaceLinks(programWords) || sedParentProtected(name, cmdCWD, home) {
						add(name, cmdCWD)
					}
				}
			}
			return true
		})
	}
	return operands, unknown
}

func literalUnresolvedProgramWrites(args []*syntax.Word, home string) ([]string, bool) {
	var paths []string
	unknown := false
	for i := 1; i+1 < len(args); i++ {
		option, ok := StaticWord(args[i], home)
		if !ok || option != "-c" && option != "-e" && option != "-E" &&
			option != "-p" && option != "--eval" {
			continue
		}
		code, ok := StaticWord(args[i+1], home)
		if !ok {
			return paths, true
		}
		for _, language := range []string{"python", "node", "perl", "ruby"} {
			found, dynamic := literalInterpreterWrites(language, code)
			paths = append(paths, found...)
			unknown = unknown || dynamic
		}
		break
	}
	return paths, unknown
}

func literalProgramWords(call *syntax.CallExpr, cwd, home string) (string, []string, bool) {
	return literalProgramWordsWithVars(call, cwd, home, nil)
}

func literalProgramWordsWithVars(call *syntax.CallExpr, cwd, home string, vars shellVariables) (string, []string, bool) {
	words := make([]string, len(call.Args))
	staticWords := make([]bool, len(call.Args))
	for i, arg := range call.Args {
		words[i], staticWords[i] = staticShellWordWithVars(arg, home, vars, shellVariablePoison{})
		if !staticWords[i] {
			words[i] = launcherAssignmentPrefix(arg)
		}
	}
	resolved := resolveLauncherWords(words, staticWords, cwd)
	if !resolved.ok || resolved.noExec || !allStatic(resolved.static) {
		return cwd, nil, false
	}
	return resolved.cwd, resolved.words, true
}

func literalInterpreterProgram(program string) bool {
	return literalLanguage(program) != ""
}

func literalInterpreterCode(program string, words []string) (string, bool) {
	language := literalLanguage(program)
	perlImports := ""
	for i := 1; i < len(words); i++ {
		word := words[i]
		if language == "perl" && strings.HasPrefix(word, "-MFile::Copy") {
			suffix := strings.TrimPrefix(word, "-MFile::Copy")
			if suffix == "" {
				perlImports = "use File::Copy; "
			} else if names, found := strings.CutPrefix(suffix, "="); found && names != "" {
				perlImports = "use File::Copy qw(" + strings.ReplaceAll(names, ",", " ") + "); "
			}
		}
		if word == "-c" && language == "python" ||
			(word == "-e" || word == "-E") && (language == "perl" || language == "ruby" || language == "node") ||
			(word == "-p" || word == "--eval" || word == "--print") && language == "node" {
			if i+1 < len(words) {
				return perlImports + words[i+1], true
			}
			return "", false
		}
		if language == "node" && strings.HasPrefix(word, "--eval=") {
			return strings.TrimPrefix(word, "--eval="), true
		}
	}
	return "", false
}

func literalReadsStdin(words []string) bool {
	sawOperand := false
	for _, word := range words[1:] {
		if word == "-c" || word == "-e" || word == "-E" || word == "-p" || word == "--eval" ||
			strings.HasPrefix(word, "--eval=") {
			return false
		}
		if word == "-" {
			return true
		}
		if word == "--" {
			sawOperand = true
			continue
		}
		if strings.HasPrefix(word, "-") && word != "-" {
			if word == "-m" || word == "-S" || word == "-x" || word == "-I" {
				continue
			}
			continue
		}
		sawOperand = true
	}
	return !sawOperand
}

func literalPipelineInterpreterInput(
	pipe *syntax.BinaryCmd, command, cwd, home string,
) (string, string, string, bool) {
	if pipe == nil || pipe.X == nil || pipe.Y == nil {
		return "", "", "", false
	}
	call, ok := pipe.Y.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", "", "", false
	}
	cmdCWD, programWords, ok := literalProgramWords(call, cwd, home)
	if !ok || len(programWords) == 0 || !literalInterpreterProgram(programBase(programWords[0])) ||
		!literalReadsStdin(programWords) {
		return "", "", "", false
	}
	code, ok := literalProducerCode(pipe.X, command, home)
	return cmdCWD, literalLanguage(programBase(programWords[0])), code, ok
}

func literalProducerCode(stmt *syntax.Stmt, command, home string) (string, bool) {
	if stmt == nil {
		return "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", false
	}
	_, words, ok := literalProgramWords(call, "", home)
	if !ok || len(words) == 0 {
		return "", false
	}
	switch programBase(words[0]) {
	case "echo":
		return strings.Join(words[1:], " ") + "\n", true
	case "printf":
		if len(words) < 2 || strings.Contains(words[1], "%") {
			return "", false
		}
		return words[1], true
	case "cat":
		for _, redirect := range stmt.Redirs {
			if (redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc) || redirect.Hdoc == nil {
				continue
			}
			start, end := int(redirect.Hdoc.Pos().Offset()), int(redirect.Hdoc.End().Offset())
			if start >= 0 && end <= len(command) && end > start {
				return command[start:end], true
			}
		}
	}
	return "", false
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
		cmdCWD, words, known := literalProgramWords(call, cwd, home)
		if !known || len(words) == 0 {
			return true
		}
		if (programBase(words[0]) == "sed" || programBase(words[0]) == "gsed") &&
			!sedFollowsInPlaceLinks(words) {
			for _, name := range sedInPlaceFiles(words) {
				if !filepath.IsAbs(name) {
					if !filepath.IsAbs(cmdCWD) {
						continue
					}
					name = OperandPath(name, cmdCWD)
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
					if link, err := os.Readlink(name); err == nil &&
						(strings.Contains(filepath.ToSlash(link), "/../") || strings.HasSuffix(filepath.ToSlash(link), "/..")) {
						replaced[name] = false
					}
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

func literalWriteMode(mode string) bool {
	return strings.ContainsAny(mode, "wax+") || mode == ">" || mode == ">>"
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
	for i := 0; i < position; i++ {
		c := code[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' {
			quote = c
		}
	}
	return quote == 0
}
