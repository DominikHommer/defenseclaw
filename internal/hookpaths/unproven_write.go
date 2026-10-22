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
	"shell-parse":          "A shell parse error leaves a protected write unproved",
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
	unprovenWriter          = regexp.MustCompile(`\b(?:open|openSync|sysopen|FileIO|writeFile\w*|appendFile\w*|File\.write|File\.binwrite|IO\.write|write_text|write_bytes|copy\w*|createWriteStream|truncate|rename|replace|move|unlink|remove)\s*\(`)
	safeNodeRead            = regexp.MustCompile(`^require\(['"]fs['"]\)\.readFile(?:Sync)?\(['"][^'"]+['"](?:,\s*\(\)=>\{\})?\)$`)
	safeNodeCopy            = regexp.MustCompile(`^require\(['"]fs['"]\)\.copyFile(?:Sync)?\(['"][^'"]+['"],\s*['"]([^'"]+)['"](?:,\s*\(\)=>\{\})?\)$`)
	safeNodeWriteData       = regexp.MustCompile(`^require\(['"]fs['"]\)\.(?:writeFileSync|appendFileSync)\((['"][^'"]+['"]),\s*(['"][^'"]+['"])\)$`)
	safePythonRead          = regexp.MustCompile(`^(?:import io;\s*)?(?:io\.)?(?:FileIO|open)\(['"][^'"]+['"],\s*['"]r['"]\)\.read\(\)$`)
	safePythonOSRead        = regexp.MustCompile(`^import os;\s*os\.open\((['"][^'"]+['"]),\s*os\.O_RDONLY\)$`)
	safePythonOpenWrite     = regexp.MustCompile(`^open\(`)
	safePythonSeparate      = regexp.MustCompile(`^open\((['"][^'"]+['"]),\s*['"]r['"]\);\s*open\((['"][^'"]+['"]),\s*['"]a['"]\)$`)
	safePythonPathWrite     = regexp.MustCompile(`^(?:from\s+pathlib\s+import\s+Path;\s*|import\s+pathlib;\s*)?(?:pathlib\.)?Path\(\s*['"]([^'"]+)['"]\s*\)\.write_(?:text|bytes)\s*\(`)
	literalPathHomeJoinOpen = regexp.MustCompile(`\b(?:pathlib\.)?Path\.home\(\)\.joinpath\(\s*['"]([^'"]+)['"]\s*\)\.open\s*\(`)
	awkBoundedAssignPrefix  = regexp.MustCompile(`^\s*BEGIN\s*\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"\\]+)"\s*;\s*print\s+"(?:\\.|[^"\\])*"\s*>>\s*$`)
	safePythonPrint         = regexp.MustCompile(`^print\(("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\)$`)
	safeRubyRead            = regexp.MustCompile(`^File\.read\(['"][^'"]+['"]\)$`)
	safeRubyOpenRead        = regexp.MustCompile(`^File\.open\((['"][^'"]+['"]),\s*['"]r['"]\)\s*\{\s*\|f\|\s*puts f\.read\s*\}$`)
	safePerlLocalCopy       = regexp.MustCompile(`^sub copy \{ return 1 \};\s*copy\(['"][^'"]+['"],\s*['"][^'"]+['"]\)$`)
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
	if !strings.ContainsAny(command, "$#*?[\\>;|&\n") &&
		!strings.Contains(command, "trap") && !strings.Contains(command, "eval") &&
		!strings.Contains(command, "source") && !strings.Contains(command, "cd ") &&
		!strings.Contains(command, "cd\t") && !strings.Contains(command, "function ") &&
		!strings.Contains(command, "function\t") && !strings.Contains(command, ". ") &&
		!strings.Contains(command, ".\t") &&
		!strings.Contains(command, "python") && !strings.Contains(command, "node") &&
		!strings.Contains(command, "ruby") && !strings.Contains(command, "perl") &&
		!strings.Contains(command, "awk") &&
		!strings.Contains(command, "()") {
		return ""
	}
	file, ok := parseShell(command)
	if !ok {
		if unprovenShellParseWrite(command, cwd, home) {
			return "shell-parse"
		}
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
		if slicesContainsString([]string{"awk", "gawk", "mawk", "nawk"}, program) {
			for _, arg := range call.Args[1:] {
				code, fixed := StaticWord(arg, home)
				if !fixed {
					var rendered strings.Builder
					if syntax.NewPrinter().Print(&rendered, arg) == nil &&
						strings.Contains(rendered.String(), "{") && strings.Contains(rendered.String(), "}") &&
						!awkUnprovenOutput(rendered.String(), cwd, home) {
						for _, target := range literalAwkRedirect.FindAllStringSubmatch(rendered.String(), -1) {
							if protectedReachPath(OperandPath(target[1], cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
								set("dynamic-argument", true)
								break
							}
						}
						continue
					}
					set("dynamic-argument", true)
					return true
				}
				if awkUnprovenOutput(code, cwd, home) {
					set("dynamic-argument", true)
					return true
				}
			}
			return true
		}
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
		if slicesContainsString([]string{"nice", "timeout", "nohup", "env", "command", "exec", "xargs"}, program) {
			words := make([]string, len(call.Args))
			allFixed := true
			for i, arg := range call.Args {
				words[i], allFixed = StaticWord(arg, home)
				if !allFixed {
					break
				}
			}
			if !allFixed {
				if unprovenWriter.MatchString(command) {
					set("dynamic-argument", true)
				}
				return true
			}
			if program == "xargs" {
				if len(literalPipelineOperands(file, called, cwd, home, depth)) == 0 &&
					unprovenWriter.MatchString(command) {
					set("dynamic-argument", true)
				}
				return true
			}
			if code, language, found := wrappedInterpreterCode(words); found {
				if class, dynamic := unprovenInterpreterCode(code, language, cwd, home); class != "" {
					set(class, dynamic)
					return true
				}
				for _, destination := range literalInterpreterWrites(code, language) {
					if protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
						set("dynamic-argument", true)
						return true
					}
				}
				if !interpreterProtectedUseSafe(code, language, cwd, home) && protectedReachFromText(code, cwd, home) {
					set("interpreter-path", true)
				}
				return true
			}
			if len(literalProgramOperands(words, nil, cwd, home, depth, false)) == 0 &&
				unprovenWriter.MatchString(command) {
				set("dynamic-argument", true)
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
							if class, dynamic := unprovenInterpreterCode(content, language, cwd, home); class != "" {
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
				if class, dynamic := unprovenInterpreterCode(code, language, cwd, home); class != "" {
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

// Recoverable syntax errors may leave executable calls and redirects in the
// syntax tree. Check those effects before discarding the failed parse.
func unprovenShellParseWrite(command, cwd, home string) bool {
	if len(command) > MaxPayloadBytes {
		return true // Beyond the command proof bound, effects are unknown.
	}
	file, _ := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.RecoverErrors(8)).Parse(strings.NewReader(command), "")
	if file == nil {
		return strings.Contains(command, ">") ||
			unprovenWriter.MatchString(command) && protectedReachFromText(command, cwd, home)
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	unknown := false
	calls := 0
	called := calledFunctions(file, home)
	syntax.Walk(file, func(node syntax.Node) bool {
		if unknown {
			return false
		}
		if declaration, ok := node.(*syntax.FuncDecl); ok {
			return declaration.Name != nil && called[declaration.Name.Value]
		}
		if call, ok := node.(*syntax.CallExpr); ok {
			calls++
			if calls > 256 {
				unknown = true
				return false
			}
			var rendered strings.Builder
			if syntax.NewPrinter().Print(&rendered, call) != nil {
				unknown = true
				return false
			}
			prefix := rendered.String()
			if unprovenProtectedWriteDepth(prefix, cwd, home, 0) != "" {
				unknown = true
				return false
			}
			for _, operand := range literalWriteOperandsDepth(prefix, cwd, home, 0) {
				if protectedReachPath(operand, protected, ssh) {
					unknown = true
					return false
				}
			}
			words := make([]string, len(call.Args))
			for i, arg := range call.Args {
				var fixed bool
				words[i], fixed = StaticWord(arg, home)
				if !fixed {
					return true // The unproven call check above handles dynamic operands.
				}
			}
			// A direct cp target is normally an ActionFacts path. The failed
			// whole-command parse discarded that fact, so recover its call as
			// a standalone command (the wrapped proof also extracts cp).
			for _, operand := range literalProgramOperands(words, nil, cwd, home, 1, false) {
				if protectedReachPath(operand, protected, ssh) {
					unknown = true
					return false
				}
			}
		}
		redirect, ok := node.(*syntax.Redirect)
		if !ok || redirect.Word == nil {
			return true
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		default:
			return true
		}
		path, fixed := StaticWord(redirect.Word, home)
		if !fixed || protectedReachPath(OperandPath(path, cwd), protected, ssh) {
			unknown = true
		}
		return !unknown
	})
	return unknown
}

// An awk print redirect opens a file. A quoted target is named by the
// literal operand extractor; an expression after > cannot be named here.
func awkUnprovenOutput(code, cwd, home string) bool {
	printing := false
	var quote byte
	for i := 0; i < len(code); i++ {
		c := code[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == ';' || c == '{' || c == '}' || c == '\n' {
			printing = false
			continue
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			start := i
			for i+1 < len(code) && ((code[i+1] >= 'a' && code[i+1] <= 'z') ||
				(code[i+1] >= 'A' && code[i+1] <= 'Z')) {
				i++
			}
			word := code[start : i+1]
			if word == "print" || word == "printf" {
				printing = true
			}
			continue
		}
		if c != '>' || !printing {
			continue
		}
		if i+1 < len(code) && code[i+1] == '>' {
			i++
		}
		for i+1 < len(code) && (code[i+1] == ' ' || code[i+1] == '\t') {
			i++
		}
		if i+1 >= len(code) {
			return true
		}
		if code[i+1] == '"' || code[i+1] == '\'' {
			quote := code[i+1]
			end := i + 2
			for end < len(code) && code[end] != quote {
				if code[end] == '\\' {
					return true // Escape semantics need an interpreter proof.
				}
				end++
			}
			if end >= len(code) {
				return true
			}
			for end+1 < len(code) && (code[end+1] == ' ' || code[end+1] == '\t') {
				end++
			}
			if end+1 < len(code) && code[end+1] != ';' && code[end+1] != '}' &&
				code[end+1] != '\n' && code[end+1] != '#' {
				return true // A later expression changes the opened target.
			}
		} else {
			start := i + 1
			end := start
			for end < len(code) && ((code[end] >= 'a' && code[end] <= 'z') ||
				(code[end] >= 'A' && code[end] <= 'Z') || code[end] == '_') {
				end++
			}
			if end == start || end < len(code) && code[end] != ' ' && code[end] != '\t' && code[end] != ';' && code[end] != '}' {
				return true
			}
			value, fixed := awkFixedAssignment(code[:start], code[start:end])
			if !fixed || protectedReachPath(OperandPath(value, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
				return true
			}
		}
	}
	return false
}

func awkFixedAssignment(prefix, name string) (string, bool) {
	// Only this complete BEGIN prefix has no intervening call or statement
	// that can change the variable or the filesystem before the redirect.
	match := awkBoundedAssignPrefix.FindStringSubmatch(prefix)
	if len(match) != 3 || match[1] != name {
		return "", false
	}
	return match[2], true
}

func wrappedInterpreterCode(words []string) (code, language string, found bool) {
	for i, word := range words {
		program := programBase(word)
		switch {
		case program == "python" || strings.HasPrefix(program, "python3"):
			if code, ok := pythonLiteralCode(words[i:]); ok {
				return code, "python", true
			}
		case program == "node" || program == "nodejs" || program == "ruby" || program == "perl":
			if i+2 < len(words) && words[i+1] == "-e" {
				if program == "nodejs" {
					program = "node"
				}
				return words[i+2], program, true
			}
		}
	}
	return "", "", false
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
		if match := safePythonSeparate.FindStringSubmatch(code); match != nil {
			destination, ok := literalString(match[2])
			if ok && !protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
				return true
			}
		}
		if safePythonOpenWrite.MatchString(code) {
			openCall, complete := literalBoundedCall(code, len("open"))
			openArgs := literalCallArgs(openCall)
			if complete && len(openArgs) == 2 {
				destination, pathOK := literalString(openArgs[0])
				mode, modeOK := literalString(openArgs[1])
				prefixEnd := len("open") + len(openCall)
				if pathOK && modeOK && literalWriteMode(mode) &&
					strings.HasPrefix(code[prefixEnd:], ".write(") {
					writeCall, writeOK := literalBoundedCall(code, prefixEnd+len(".write"))
					writeArgs := literalCallArgs(writeCall)
					if writeOK && len(writeArgs) == 1 && pythonLiteralData(writeArgs[0]) &&
						strings.Trim(strings.TrimSpace(code[prefixEnd+len(".write")+len(writeCall):]), "; ") == "" &&
						!protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
						return true
					}
				}
			}
		}
		if match := safePythonPathWrite.FindStringSubmatchIndex(code); match != nil {
			call, complete := literalBoundedCall(code, match[1]-1)
			args := literalCallArgs(call)
			if complete && len(args) == 1 {
				dataOK := pythonLiteralData(args[0])
				destination := code[match[2]:match[3]]
				if dataOK && strings.Trim(strings.TrimSpace(code[match[1]-1+len(call):]), "; ") == "" &&
					!protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
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

func pythonLiteralData(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) > 1 && value[0] == 'b' {
		value = value[1:]
	}
	if len(value) < 2 || value[0] != value[len(value)-1] ||
		value[0] != '\'' && value[0] != '"' {
		return false
	}
	quote := value[0]
	for i := 1; i < len(value)-1; i++ {
		switch value[i] {
		case '\\':
			i++
			if i >= len(value)-1 {
				return false
			}
		case quote:
			return false
		}
	}
	return true
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
				} else if class, _ := unprovenInterpreterCode(code, program, cwd, home); class != "" {
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

func unprovenInterpreterCode(code, language, cwd, home string) (string, bool) {
	if len(code) > 16<<10 {
		return "interpreter-path", true
	}
	if language == "python" || strings.HasPrefix(language, "python3") {
		for _, location := range literalCopyCall.FindAllStringIndex(code, -1) {
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
	for _, location := range unprovenWriter.FindAllStringIndex(code, -1) {
		call, ok := literalBoundedCall(code, location[1]-1)
		if !ok {
			return "interpreter-path", true
		}
		args := literalCallArgs(call)
		if len(args) == 0 {
			return "interpreter-path", true
		}
		name := code[location[0] : location[1]-1]
		if language == "python" || strings.HasPrefix(language, "python3") {
			if name == "write_text" || name == "write_bytes" {
				// The first call argument is data. The file is the Path
				// receiver, which must have a fixed ordinary destination.
				fixedReceiver := false
				for _, match := range literalPathWrite.FindAllStringSubmatchIndex(code, -1) {
					if match[1] == location[1] {
						fixedReceiver = true
						break
					}
				}
				if !fixedReceiver {
					return "interpreter-path", true
				}
				continue
			}
			if name == "open" && location[0] > 0 && code[location[0]-1] == '.' &&
				strings.Contains(code[:location[0]], "Path.home()") && len(args) > 0 {
				if mode, ok := literalString(args[0]); ok && literalWriteMode(mode) {
					safePath := false
					for _, match := range literalPathHomeJoinOpen.FindAllStringSubmatchIndex(code, -1) {
						if match[1] != location[1] {
							continue
						}
						relative := code[match[2]:match[3]]
						if !filepath.IsAbs(relative) && !strings.Contains(relative, "..") {
							destination := OperandPath(relative, home)
							if !protectedReachPath(destination, newProtectedFiles(home), filepath.Join(home, ".ssh")) {
								safePath = true
							}
						}
						break
					}
					if safePath {
						continue
					}
					return "interpreter-path", true
				}
			}
		}
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
