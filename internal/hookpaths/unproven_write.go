// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// UnprovenReasonKey is positive evidence that a command can reach a protected
// file through a construct whose write target the bounded proof cannot name.
// The value is a short, fixed class name, never command or filesystem data.
const UnprovenReasonKey = "\x00unproven-write"

var unprovenReasonTitles = map[string]string{
	"trap":                 "A trap handler can write a protected file",
	"function":             "A called function can write a protected file",
	"dynamic-command":      "A dynamic command can write a protected file",
	"dynamic-argument":     "A dynamic argument can select a protected file",
	"eval-source":          "Evaluated or sourced code can write a protected file",
	"interpreter-path":     "Interpreter file effects cannot be proved safe for the protected path",
	"interpreter-argument": "An interpreter has a dynamic argument after writable code",
	"copy-directory":       "A copy into a directory can select a protected file",
	"cdpath":               "CDPATH can select a directory containing a protected file link",
}

// UnprovenWriteTitle gives the operator the class that prevented a proof.
func UnprovenWriteTitle(reason string) string {
	return unprovenReasonTitles[reason]
}

var (
	unprovenPathToken  = regexp.MustCompile(`[A-Za-z0-9_./~*?\[\]-]+`)
	unprovenQuotedPath = []*regexp.Regexp{
		regexp.MustCompile(`'([^']+)'`),
		regexp.MustCompile(`"([^"]+)"`),
	}
	unprovenWriter      = regexp.MustCompile(`\b(?:open|openSync|sysopen|FileIO|writeFile\w*|appendFile\w*|File\.write|File\.binwrite|IO\.write|write_text|write_bytes|copy\w*|createWriteStream|truncate|rename|replace|move|unlink|remove)\s*\(`)
	safeNodeRead        = regexp.MustCompile(`^require\(['"]fs['"]\)\.readFile(?:Sync)?\(['"][^'"]+['"](?:,\s*\(\)=>\{\})?\)$`)
	safeNodeCopy        = regexp.MustCompile(`^require\(['"]fs['"]\)\.copyFile(?:Sync)?\(['"][^'"]+['"],\s*['"]([^'"]+)['"](?:,\s*\(\)=>\{\})?\)$`)
	safeNodeWriteData   = regexp.MustCompile(`^require\(['"]fs['"]\)\.(?:writeFileSync|appendFileSync)\((['"][^'"]+['"]),\s*(['"][^'"]+['"])\)$`)
	safePythonRead      = regexp.MustCompile(`^(?:import io;\s*)?(?:io\.)?(?:FileIO|open)\(['"][^'"]+['"],\s*['"]r['"]\)\.read\(\)$`)
	safePythonOSRead    = regexp.MustCompile(`^import os;\s*os\.open\((['"][^'"]+['"]),\s*os\.O_RDONLY\)$`)
	safePythonWriteData = regexp.MustCompile(`^open\((['"][^'"]+['"]),\s*['"]a['"]\)\.write\((['"][^'"]+['"])\)$`)
	safePythonSeparate  = regexp.MustCompile(`^open\((['"][^'"]+['"]),\s*['"]r['"]\);\s*open\((['"][^'"]+['"]),\s*['"]a['"]\)$`)
	safePythonPrint     = regexp.MustCompile(`^print\(("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\)$`)
	safeRubyRead        = regexp.MustCompile(`^File\.read\(['"][^'"]+['"]\)$`)
	safeRubyOpenRead    = regexp.MustCompile(`^File\.open\((['"][^'"]+['"]),\s*['"]r['"]\)\s*\{\s*\|f\|\s*puts f\.read\s*\}$`)
	safePerlLocalCopy   = regexp.MustCompile(`^sub copy \{ return 1 \};\s*copy\(['"][^'"]+['"],\s*['"][^'"]+['"]\)$`)
)

// UnprovenProtectedWrite is the boundary between exact write extraction and
// execution forms it cannot model. It returns a class only if the command has
// such a form and a path in its bounded text can reach a protected file. A
// dynamic interpreter write operand can name the protected file directly.
func UnprovenProtectedWrite(command, cwd, home string) string {
	return unprovenProtectedWriteDepth(command, cwd, home, 0)
}

func unprovenProtectedWriteDepth(command, cwd, home string, depth int) string {
	if command == "" || home == "" || !filepath.IsAbs(cwd) || len(command) > MaxPayloadBytes {
		return ""
	}
	if depth >= 4 {
		if protectedReachFromText(command, cwd, home) {
			return "dynamic-command"
		}
		return ""
	}
	if !strings.ContainsAny(command, "$#*?[\\") &&
		!strings.Contains(command, "trap") && !strings.Contains(command, "eval") &&
		!strings.Contains(command, "source") && !strings.Contains(command, "cd ") &&
		!strings.Contains(command, "cd\t") && !strings.Contains(command, "function ") &&
		!strings.Contains(command, "function\t") && !strings.Contains(command, ". ") &&
		!strings.Contains(command, ".\t") &&
		!strings.Contains(command, "python") && !strings.Contains(command, "node") &&
		!strings.Contains(command, "ruby") && !strings.Contains(command, "perl") &&
		!strings.Contains(command, "()") {
		return ""
	}
	file, ok := parseShell(command)
	if !ok {
		return ""
	}
	reachable := false
	called := calledFunctions(file, home)
	reachText := command
	if strings.Contains(command, "()") || strings.Contains(command, "function ") {
		reachText = reachableShellWords(file, called, home)
	}
	checkReach := func() bool {
		if !reachable {
			reachable = samePathName(cwd, home) || samePathName(cwd, filepath.Join(home, ".ssh")) ||
				protectedReachFromText(reachText, cwd, home)
		}
		return reachable
	}
	reason := ""
	set := func(class string, dynamicPath bool) {
		if reason == "" && (dynamicPath || checkReach()) {
			reason = class
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if reason != "" {
			return false
		}
		if redirect, ok := node.(*syntax.Redirect); ok && redirect.Word != nil {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
				if _, fixed := StaticWord(redirect.Word, home); !fixed {
					if !provenBoundedRedirect(file, redirect, cwd, home) {
						var target strings.Builder
						runtimeExpansion := false
						syntax.Walk(redirect.Word, func(part syntax.Node) bool {
							switch part.(type) {
							case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst:
								runtimeExpansion = true
							}
							return !runtimeExpansion
						})
						if syntax.NewPrinter().Print(&target, redirect.Word) != nil ||
							protectedReachFromText(target.String(), cwd, home) ||
							runtimeExpansion && checkReach() {
							set("dynamic-argument", true)
						}
					}
				}
			}
			return true
		}
		if function, ok := node.(*syntax.FuncDecl); ok {
			if function.Name == nil || !called[function.Name.Value] {
				return false
			}
			if functionBodyMayWrite(function.Body, cwd, home) {
				set("function", false)
			}
			return true
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		program, static := StaticWord(call.Args[0], home)
		if !static {
			set("dynamic-command", false)
			return true
		}
		program = programBase(program)
		if program == "trap" {
			set("trap", false)
			return true
		}
		if program == "eval" || program == "source" || program == "." {
			for _, argument := range call.Args[1:] {
				if _, ok := StaticWord(argument, home); !ok {
					set("eval-source", true)
					return true
				}
			}
			if (program == "source" || program == ".") && len(call.Args) >= 2 {
				if name, ok := StaticWord(call.Args[1], home); ok {
					if content, ok := readIndirectSource(name, cwd); ok && protectedReachFromText(content, cwd, home) {
						set("eval-source", true)
						return true
					}
				}
			}
			set("eval-source", false)
			return true
		}
		if program == "cd" {
			if cdPathProtectedReach(call, file, cwd, home) {
				set("cdpath", true)
			}
			return true
		}
		if (program == "sh" || program == "bash") && len(call.Args) >= 3 {
			if option, ok := StaticWord(call.Args[1], home); ok && option == "-c" {
				if code, fixed := StaticWord(call.Args[2], home); fixed {
					if nested := unprovenProtectedWriteDepth(code, cwd, home, depth+1); nested != "" {
						set(nested, true)
					}
				} else {
					set("dynamic-argument", false)
				}
				return true
			}
		}
		if program == "python" || strings.HasPrefix(program, "python3") ||
			program == "node" || program == "nodejs" || program == "ruby" || program == "perl" {
			language := program
			if language == "nodejs" {
				language = "node"
			}
			code, codeIndex, fixed := interpreterCodeOperand(call, language, home)
			if !fixed {
				// Unknown options, code operands and script files cannot
				// certify the destination of a protected alias named by the
				// call. A small regular script under cwd is also inspected.
				if len(call.Args) >= 2 {
					if script, static := StaticWord(call.Args[1], home); static {
						if content, ok := readIndirectSource(script, cwd); ok {
							if class, dynamic := unprovenInterpreterCode(content, language, cwd, home, !pythonCallSetsImportPath(call)); class != "" {
								set(class, dynamic)
							}
							if protectedReachFromText(content, cwd, home) &&
								!interpreterProtectedUseSafe(content, language, cwd, home) {
								set("interpreter-path", true)
							}
						}
					}
				}
				set("interpreter-path", false)
				return true
			}
			if fixed && unprovenWriter.MatchString(code) {
				if class, dynamic := unprovenInterpreterCode(code, language, cwd, home, !pythonCallSetsImportPath(call)); class != "" {
					set(class, dynamic)
				}
				for _, argument := range call.Args[codeIndex+1:] {
					if _, ok := StaticWord(argument, home); !ok {
						set("interpreter-argument", false)
						break
					}
				}
			}
			// Source scanning recognizes selected write APIs, but a fixed
			// interpreter script can invoke any other API. When it names a
			// protected alias, only the small read/source-only forms below
			// establish that the alias cannot be a write destination.
			if fixed && reason == "" && !interpreterProtectedUseSafe(code, language, cwd, home) &&
				checkReach() {
				set("interpreter-path", true)
			}
			return true
		}
		if !slicesContainsString(dataPrograms, program) {
			if slicesContainsString([]string{"cp", "gcp", "mv", "gmv", "install"}, program) && len(call.Args) > 1 {
				if _, ok := StaticWord(call.Args[len(call.Args)-1], home); !ok {
					if destination, bounded := boundedCommandDestination(file, call, home); bounded {
						if protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
							set("dynamic-argument", true)
						}
						return true
					}
					set("dynamic-argument", true)
					return true
				}
			}
			if slicesContainsString([]string{"tee", "touch", "truncate"}, program) {
				for _, argument := range call.Args[1:] {
					if _, ok := StaticWord(argument, home); !ok {
						set("dynamic-argument", false)
						return true
					}
				}
			}
			for _, argument := range call.Args[1:] {
				if _, ok := StaticWord(argument, home); !ok {
					set("dynamic-argument", false)
					break
				}
			}
		}
		return true
	})
	return reason
}

// A quoted value fixed by the preceding printf assignment is already a
// complete redirect proof. Its literal '*' must not be treated as a glob.
func provenBoundedRedirect(file *syntax.File, redirect *syntax.Redirect, cwd, home string) bool {
	if len(file.Stmts) != 2 || len(file.Stmts[1].Redirs) != 1 || file.Stmts[1].Redirs[0] != redirect {
		return false
	}
	name, value, ok := boundedPrintfAssignment(file.Stmts[0], home)
	if !ok || !boundedWordUses(redirect.Word, name) || boundedWordPattern(redirect.Word, name, value) {
		return false
	}
	target, known := boundedWord(redirect.Word, home, name, value)
	return known && target != "" && !protectedReachPath(OperandPath(target, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh"))
}

func interpreterProtectedUseSafe(code, language, cwd, home string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return true
	}
	commentOnly := true
	for _, line := range strings.Split(code, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			commentOnly = false
			break
		}
	}
	if commentOnly {
		return true
	}
	if language == "python" || strings.HasPrefix(language, "python3") {
		if safePythonRead.MatchString(code) || safePythonPrint.MatchString(code) {
			return true
		}
		if match := safePythonOSRead.FindStringSubmatch(code); match != nil {
			_, ok := literalString(match[1])
			return ok
		}
		for _, pattern := range []*regexp.Regexp{safePythonWriteData, safePythonSeparate} {
			if match := pattern.FindStringSubmatch(code); match != nil {
				destination, ok := literalString(match[2])
				if pattern == safePythonWriteData {
					destination, ok = literalString(match[1])
				}
				if ok && !protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
					return true
				}
			}
		}
		return false
	}
	switch language {
	case "node":
		if safeNodeRead.MatchString(code) {
			return true
		}
		if match := safeNodeCopy.FindStringSubmatch(code); match != nil {
			return !protectedReachPath(OperandPath(match[1], cwd), newProtectedFiles(home), filepath.Join(home, ".ssh"))
		}
		if match := safeNodeWriteData.FindStringSubmatch(code); match != nil {
			destination, ok := literalString(match[1])
			_, dataOK := literalString(match[2])
			return ok && dataOK && !protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh"))
		}
	case "ruby":
		return safeRubyRead.MatchString(code) || safeRubyOpenRead.MatchString(code)
	case "perl":
		return safePerlLocalCopy.MatchString(code)
	}
	return false
}

// boundedCommandDestination handles a single assignment or a single called
// function whose literal argument fixes the copy destination. No intervening
// statement can change the value or the directory in either shape.
func boundedCommandDestination(file *syntax.File, call *syntax.CallExpr, home string) (string, bool) {
	if len(file.Stmts) != 2 || len(call.Args) < 2 {
		return "", false
	}
	last := call.Args[len(call.Args)-1]
	if file.Stmts[1].Cmd == call {
		if name, value, ok := boundedSimpleAssignment(file.Stmts[0], home); ok {
			return boundedWord(last, home, name, value)
		}
		if name, value, ok := boundedBasenameAssignment(file.Stmts[0], home); ok {
			return boundedWord(last, home, name, value)
		}
	}
	function, ok := file.Stmts[0].Cmd.(*syntax.FuncDecl)
	if !ok || function.Name == nil || function.Body == nil {
		return "", false
	}
	body, ok := function.Body.Cmd.(*syntax.Block)
	if !ok || len(body.Stmts) != 1 || body.Stmts[0].Cmd != call {
		return "", false
	}
	invoke, ok := file.Stmts[1].Cmd.(*syntax.CallExpr)
	if !ok || len(invoke.Args) < 2 || len(invoke.Assigns) != 0 || len(file.Stmts[1].Redirs) != 0 {
		return "", false
	}
	name, static := StaticWord(invoke.Args[0], home)
	if !static || name != function.Name.Value {
		return "", false
	}
	for position, argument := range invoke.Args[1:] {
		value, ok := StaticWord(argument, home)
		if !ok {
			return "", false
		}
		if result, ok := boundedWord(last, home, strconv.Itoa(position+1), value); ok {
			return result, true
		}
	}
	return "", false
}

func boundedBasenameAssignment(stmt *syntax.Stmt, home string) (name, value string, ok bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return "", "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return "", "", false
	}
	assignment := call.Assigns[0]
	if assignment.Name == nil || assignment.Value == nil || len(assignment.Value.Parts) != 1 {
		return "", "", false
	}
	part := assignment.Value.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok && len(quoted.Parts) == 1 {
		part = quoted.Parts[0]
	}
	substitution, ok := part.(*syntax.CmdSubst)
	if !ok || len(substitution.Stmts) != 1 {
		return "", "", false
	}
	basename, ok := substitution.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(basename.Args) != 2 || len(basename.Assigns) != 0 || len(substitution.Stmts[0].Redirs) != 0 {
		return "", "", false
	}
	program, static := StaticWord(basename.Args[0], home)
	if !static || program != "basename" {
		return "", "", false
	}
	path, static := StaticWord(basename.Args[1], home)
	if !static || path == "" || strings.ContainsAny(path, "\x00\r\n") {
		return "", "", false
	}
	return assignment.Name.Value, filepath.Base(path), true
}

func reachableShellWords(file *syntax.File, called map[string]bool, home string) string {
	var text strings.Builder
	syntax.Walk(file, func(node syntax.Node) bool {
		if function, ok := node.(*syntax.FuncDecl); ok {
			return function.Name != nil && called[function.Name.Value]
		}
		if word, ok := node.(*syntax.Word); ok {
			if value, static := StaticWord(word, home); static {
				text.WriteString(value)
			} else {
				_ = syntax.NewPrinter().Print(&text, word)
			}
			text.WriteByte(' ')
			return false
		}
		return true
	})
	return text.String()
}

func slicesContainsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func functionBodyMayWrite(body *syntax.Stmt, cwd, home string) bool {
	mayWrite := false
	syntax.Walk(body, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
				mayWrite = true
			}
		}
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			program, static := StaticWord(call.Args[0], home)
			program = programBase(program)
			if program == "python" || strings.HasPrefix(program, "python3") ||
				program == "node" || program == "nodejs" || program == "ruby" || program == "perl" {
				code, _, fixed := interpreterCodeOperand(call, program, home)
				if !fixed || len(literalInterpreterWrites(code, program)) > 0 {
					mayWrite = true
				} else if class, _ := unprovenInterpreterCode(code, program, cwd, home, !pythonCallSetsImportPath(call)); class != "" {
					mayWrite = true
				}
			} else if !static || !slicesContainsString(dataPrograms, program) &&
				!slicesContainsString([]string{":", "true", "false", "pwd"}, program) {
				mayWrite = true
			}
		}
		return !mayWrite
	})
	return mayWrite
}

func interpreterCodeOperand(call *syntax.CallExpr, program, home string) (string, int, bool) {
	words := make([]string, len(call.Args))
	for i, word := range call.Args {
		var ok bool
		words[i], ok = StaticWord(word, home)
		if !ok {
			return "", 0, false
		}
		if (program == "node" || program == "ruby" || program == "perl") && i == 2 && words[1] == "-e" {
			return words[2], 2, true
		}
		if (program == "python" || strings.HasPrefix(program, "python3")) && words[i] == "-c" && i+1 < len(words) {
			code, ok := StaticWord(call.Args[i+1], home)
			return code, i + 1, ok
		}
	}
	return "", 0, false
}

// PythonInertTextMasked is set by internal/guardrail, which imports this
// package: it returns Python source with the string text that provably runs
// nothing blanked at the same offsets (guardrail.MaskPythonStrings when
// guardrail.PythonStringsMayRun says the strings cannot run from cwd), or the
// source unchanged. Unset, every byte counts (fail closed). T5 integration of
// g-hooks-wp's class rule with g-hooks-parse's inert Python text: a write
// call spelled only inside an inert string is not interpreter code.
var PythonInertTextMasked func(code, cwd string) string

// pythonCallSetsImportPath reports whether the shell call assigns PYTHONPATH
// or PYTHONHOME (or anything the check cannot name): a module from another
// directory can then run string text, so none of it is inert.
func pythonCallSetsImportPath(call *syntax.CallExpr) bool {
	for _, assignment := range call.Assigns {
		if assignment.Name == nil {
			return true
		}
		switch assignment.Name.Value {
		case "PYTHONPATH", "PYTHONHOME":
			return true
		}
	}
	return false
}

func unprovenInterpreterCode(code, language, cwd, home string, maskInert bool) (string, bool) {
	if len(code) > 16<<10 {
		return "interpreter-path", true
	}
	// scan finds the write calls; code still supplies their arguments, at
	// the same offsets.
	scan := code
	if maskInert && PythonInertTextMasked != nil && (language == "python" || strings.HasPrefix(language, "python3")) {
		if masked := PythonInertTextMasked(code, cwd); len(masked) == len(code) {
			scan = masked
		}
	}
	if language == "python" || strings.HasPrefix(language, "python3") {
		for _, location := range literalCopyCall.FindAllStringIndex(scan, -1) {
			api := strings.TrimSuffix(code[location[0]:location[1]], "(")
			if api != "shutil.copy" && api != "shutil.copy2" {
				continue
			}
			call, ok := literalBoundedCall(code, location[1]-1)
			if !ok {
				return "interpreter-path", true
			}
			args := literalCallArgs(call)
			dst := literalCallArgument(args, 1, "dst")
			name, ok := literalString(dst)
			if !ok {
				return "interpreter-path", true
			}
			if info, err := os.Stat(OperandPath(name, cwd)); err == nil && info.IsDir() {
				destination := OperandPath(name, cwd)
				protected := newProtectedFiles(home)
				ssh := filepath.Join(home, ".ssh")
				source, sourceOK := literalString(literalCallArgument(args, 0, "src"))
				if !sourceOK {
					if protectedReachPath(destination, protected, ssh) {
						return "copy-directory", true
					}
					directory, err := os.Open(destination)
					if err != nil {
						return "copy-directory", true
					}
					entries, err := directory.Readdirnames(257)
					_ = directory.Close()
					if err != nil && err != io.EOF || len(entries) > 256 {
						return "copy-directory", true
					}
					for _, entry := range entries {
						if protectedReachPath(filepath.Join(destination, entry), protected, ssh) {
							return "copy-directory", true
						}
					}
					continue
				}
				// shutil.copy/copy2 choose the basename of src when dst is
				// a directory. Inspect that child, including a linked dst.
				child := OperandPath(filepath.Base(source), destination)
				if protectedReachPath(child, protected, ssh) {
					return "copy-directory", true
				}
			}
		}
	}
	for _, location := range unprovenWriter.FindAllStringIndex(scan, -1) {
		call, ok := literalBoundedCall(code, location[1]-1)
		if !ok {
			return "interpreter-path", true
		}
		args := literalCallArgs(call)
		if len(args) == 0 {
			return "interpreter-path", true
		}
		name := code[location[0] : location[1]-1]
		if slicesContainsString([]string{"truncate", "rename", "replace", "move", "unlink", "remove", "sysopen", "IO.write"}, name) {
			pathArgs := args[:1]
			if name == "sysopen" && len(args) >= 2 {
				pathArgs = args[1:2]
			} else if (name == "rename" || name == "replace" || name == "move") && len(args) >= 2 {
				pathArgs = args[:2]
			}
			for _, arg := range pathArgs {
				if _, ok := literalString(arg); !ok {
					return "interpreter-path", true
				}
			}
			return "interpreter-path", false
		}
		if strings.HasPrefix(name, "copy") || name == "copy" {
			if len(args) < 2 {
				return "interpreter-path", true
			}
			if _, ok := literalString(args[1]); !ok {
				return "interpreter-path", true
			}
			continue
		}
		if name == "open" || name == "openSync" || name == "FileIO" {
			pathArg, modeArg := args[0], ""
			if language == "perl" && len(args) >= 3 {
				pathArg, modeArg = args[2], args[1]
			} else if len(args) >= 2 {
				modeArg = args[1]
			}
			if (language == "python" || strings.HasPrefix(language, "python3")) && strings.HasSuffix(code[:location[0]], "os.") {
				if !literalOSWriteFlags(modeArg) {
					continue
				}
			} else if mode, ok := literalString(modeArg); !ok || !literalWriteMode(mode) {
				continue
			}
			if _, ok := literalString(pathArg); !ok {
				return "interpreter-path", true
			}
			continue
		}
		if _, ok := literalString(args[0]); !ok {
			return "interpreter-path", true
		}
	}
	return "", false
}

func protectedReachFromText(command, cwd, home string) bool {
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	seen := map[string]bool{}
	text := strings.ReplaceAll(strings.ReplaceAll(command, "${HOME}/", home+"/"), "$HOME/", home+"/")
	for _, quoted := range unprovenQuotedPath {
		matches := quoted.FindAllStringSubmatch(text, 257)
		if len(matches) > 256 {
			return true
		}
		for _, match := range matches {
			if len(match[1]) > MaxWriteTargetPathBytes || unprovenPathToken.FindString(match[1]) == match[1] {
				continue
			}
			candidate := match[1]
			if candidate == "~" || strings.HasPrefix(candidate, "~/") {
				candidate = filepath.Join(home, strings.TrimPrefix(candidate, "~/"))
			}
			if protectedReachTextPath(OperandPath(candidate, cwd), protected, ssh) {
				return true
			}
		}
	}
	tokens := unprovenPathToken.FindAllString(text, 513)
	if len(tokens) > 512 {
		return true // The path reach scan itself exceeded its proof bound.
	}
	for _, token := range tokens {
		if seen[token] || len(token) > MaxWriteTargetPathBytes || token == "." || token == ".." {
			continue
		}
		seen[token] = true
		if strings.ContainsAny(token, "*?[]") {
			if boundedProtectedGlobReach(token, cwd, protected, ssh) {
				return true
			}
			continue
		}
		if token == "~" || strings.HasPrefix(token, "~/") {
			token = filepath.Join(home, strings.TrimPrefix(token, "~/"))
		}
		if protectedReachTextPath(OperandPath(token, cwd), protected, ssh) {
			return true
		}
	}
	return false
}

func boundedProtectedGlobReach(pattern, cwd string, protected protectedFiles, ssh string) bool {
	parent, base := filepath.Dir(pattern), filepath.Base(pattern)
	if _, err := filepath.Match(base, ""); err != nil {
		return false // An incomplete URL bracket is not a shell glob.
	}
	if strings.ContainsAny(parent, "*?[") {
		return true
	}
	directory, err := os.Open(OperandPath(parent, cwd))
	if err != nil {
		return false
	}
	names, err := directory.Readdirnames(4097)
	_ = directory.Close()
	if err != nil && err != io.EOF || len(names) > 4096 {
		return true
	}
	for _, name := range names {
		if matched, _ := filepath.Match(base, name); matched &&
			protectedReachPath(OperandPath(name, OperandPath(parent, cwd)), protected, ssh) {
			return true
		}
	}
	return false
}

func protectedReachPath(path string, protected protectedFiles, ssh string) bool {
	resolved, ok := ResolveWriteTarget(path)
	if !ok {
		return false
	}
	if protected.has(resolved) || samePathName(resolved, ssh) {
		return true
	}
	if mapped, ok := protected.target(resolved); ok && protected.has(mapped) {
		return true
	}
	return false
}

// The user's home is a reachability clue for unmodelled code: relative
// interpreter paths and shell state can enter its protected subdirectories.
// Exact write destinations still use protectedReachPath, so a literal
// ordinary child of home is not mistaken for the protected file.
func protectedReachTextPath(path string, protected protectedFiles, ssh string) bool {
	resolved, ok := ResolveWriteTarget(path)
	return ok && samePathName(resolved, filepath.Dir(ssh)) || protectedReachPath(path, protected, ssh)
}

func cdPathProtectedReach(call *syntax.CallExpr, file *syntax.File, cwd, home string) bool {
	if len(call.Args) != 2 {
		return false
	}
	path, ok := StaticWord(call.Args[1], home)
	if !ok || cdBypassesSearchPath(path) || path == "" || strings.HasPrefix(path, "-") {
		return false
	}
	selected := OperandPath(path, filepath.Join(home, ".ssh"))
	info, err := os.Stat(selected)
	if err != nil || !info.IsDir() {
		return false
	}
	protected := newProtectedFiles(home)
	var rendered strings.Builder
	if syntax.NewPrinter().Print(&rendered, file) != nil {
		return false
	}
	operands, _, _ := ShellWriteOperands(rendered.String(), cwd, home)
	operands = append(operands, LiteralWriteOperands(rendered.String(), cwd, home)...)
	for _, operand := range operands {
		if relative, err := filepath.Rel(cwd, operand); err == nil && relative != "." && !strings.HasPrefix(relative, "..") {
			if protectedReachPath(OperandPath(relative, selected), protected, filepath.Join(home, ".ssh")) {
				return true
			}
		}
	}
	return false
}
