// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type tarOptionSpec struct {
	name      string
	short     byte
	value     bool
	directory bool
	optional  bool
	command   bool
	transform bool
}

// tarOptionSpecs lists options that cannot run a child program or move an
// extracted member outside the selected destination.
var tarOptionSpecs = []tarOptionSpec{
	{name: "directory", short: 'C', value: true, directory: true},
	{name: "dir", value: true, directory: true},
	{name: "cd", value: true, directory: true},
	{name: "one-top-level", directory: true, optional: true},
	{name: "file", short: 'f', value: true},
	{name: "exclude", value: true},
	{name: "strip-components", value: true},
	{name: "checkpoint", value: true},
	{name: "totals", optional: true},
	{name: "create", short: 'c'},
	{name: "extract", short: 'x'},
	{name: "get"},
	{name: "list", short: 't'},
	{name: "overwrite"},
	{name: "keep-old-files"},
	{name: "skip-old-files"},
	{name: "no-same-owner"},
	{name: "no-same-permissions"},
	{name: "gzip", short: 'z'},
	{name: "bzip2", short: 'j'},
	{name: "xz", short: 'J'},
	{name: "zstd"},
	{name: "auto-compress", short: 'a'},
	{name: "verbose", short: 'v'},
	{name: "wildcards"},
	{name: "to-command", value: true, command: true},
	{name: "use-compress-program", short: 'I', value: true, command: true},
	{name: "checkpoint-action", value: true, command: true},
	{name: "info-script", short: 'F', value: true, command: true},
	{name: "new-volume-script", value: true, command: true},
	{name: "rmt-command", value: true, command: true},
	{name: "rsh-command", short: 'e', value: true, command: true},
	{name: "transform", short: 's', value: true, transform: true},
	{name: "xform", value: true, transform: true},
	{short: 'k'}, {short: 'O'}, {short: 'p'}, {short: 'h'},
	{short: 'm'}, {short: 'w'}, {short: 'U'},
	{short: 'T', value: true}, {short: 'X', value: true},
}

func tarLongOption(name string) (tarOptionSpec, bool) {
	names := make([]string, 0, len(tarOptionSpecs))
	for _, option := range tarOptionSpecs {
		if option.name != "" {
			names = append(names, option.name)
		}
	}
	resolved, unique := longOption(name, names)
	if !unique || resolved == "" {
		return tarOptionSpec{}, false
	}
	for _, option := range tarOptionSpecs {
		if option.name == resolved {
			return option, true
		}
	}
	return tarOptionSpec{}, false
}

func tarShortOption(letter byte) (tarOptionSpec, bool) {
	for _, option := range tarOptionSpecs {
		if option.short == letter {
			return option, true
		}
	}
	return tarOptionSpec{}, false
}

func tarProgram(program string) bool {
	switch program {
	case "tar", "gtar", "bsdtar":
		return true
	}
	return false
}

func tarTransformRunsCommand(expression string) bool {
	if len(expression) < 4 || expression[0] != 's' {
		return true
	}
	delimiter := expression[1]
	separators := 0
	escaped := false
	for i := 2; i < len(expression); i++ {
		if escaped {
			escaped = false
			continue
		}
		if expression[i] == '\\' {
			escaped = true
			continue
		}
		if expression[i] != delimiter {
			continue
		}
		separators++
		if separators == 2 {
			flags := expression[i+1:]
			return strings.ContainsRune(flags, 'e') || strings.Trim(flags, "gi") != ""
		}
	}
	return true
}

// ShellExecutableOptionUnknown reports an option that can run program text
// or whose grammar is not known. Both the hook and gateway use this result.
func ShellExecutableOptionUnknown(command, cwd, home string) (unknown bool) {
	defer recoverAnalysisPanic(func() { unknown = true })
	contexts, _ := shellAnalysisScripts(command, cwd, home)
	for _, context := range contexts {
		states := shellWordStates(context.file, home, shellVariablePoison{})
		syntax.Walk(context.file, func(node syntax.Node) bool {
			if _, declared := node.(*syntax.FuncDecl); declared {
				return false
			}
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 || context.handled[int(call.Pos().Offset())] {
				return true
			}
			words := make([]string, len(call.Args))
			static := make([]bool, len(call.Args))
			for i, word := range call.Args {
				words[i], static[i] = shellStaticWordWithKnownCalls(word, home, context.cwd, states.varsFor(word), shellVariablePoison{})
				if !static[i] {
					words[i] = launcherAssignmentPrefix(word)
				}
			}
			if !static[0] {
				return true
			}
			resolved := resolveLauncherWords(words, static, context.cwd)
			if !resolved.ok {
				if tarProgram(programBase(words[0])) {
					unknown = true
					return false
				}
				if _, launcher := launcherSpecs[programBase(words[0])]; launcher {
					for _, candidate := range words[1:] {
						name := programBase(candidate)
						if launcherWriterProgram(name) || launcherSpecs[name].kind == launcherShell ||
							launcherSpecs[name].kind == launcherScript || name == "eval" {
							unknown = true
							return false
						}
					}
				}
				return true
			}
			if len(resolved.words) != 0 && resolved.static[0] && tarProgram(programBase(resolved.words[0])) {
				parsed := parseTarOptions(resolved.words[1:], resolved.static[1:], resolved.cwd)
				if !parsed.known || parsed.executable {
					unknown = true
					return false
				}
			}
			return true
		})
		if unknown {
			return true
		}
	}
	return false
}
