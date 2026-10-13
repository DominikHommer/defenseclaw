// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type launcherKind uint8

const (
	launcherProgram launcherKind = iota
	launcherEnv
	launcherShell
	launcherScript
	launcherFind
	launcherFlock
	launcherXargs
)

type launcherSpec struct {
	kind                  launcherKind
	shortFlags, shortArgs string
	longFlags, longArgs   []string
	longOptional          []string
	positionals           int
}

// Every command prefix uses this option description before its child is read.
var launcherSpecs = map[string]launcherSpec{
	"env":         {kind: launcherEnv},
	"command":     {shortFlags: "pVv"},
	"builtin":     {},
	"exec":        {shortFlags: "cl", shortArgs: "a"},
	"nohup":       {longFlags: []string{"help", "version"}},
	"nice":        {shortArgs: "n", longArgs: []string{"adjustment"}},
	"timeout":     {shortFlags: "v", shortArgs: "sk", longFlags: []string{"foreground", "preserve-status", "verbose", "help", "version"}, longArgs: []string{"signal", "kill-after"}, positionals: 1},
	"stdbuf":      {shortArgs: "ioe", longArgs: []string{"input", "output", "error"}},
	"setsid":      {shortFlags: "cfw", longFlags: []string{"ctty", "fork", "wait"}},
	"chrt":        {shortFlags: "abfiorvmp", shortArgs: "TtP", longFlags: []string{"all-tasks", "batch", "fifo", "idle", "other", "rr", "verbose", "max", "pid", "help", "version"}, longArgs: []string{"sched-runtime", "sched-deadline", "sched-period"}, positionals: 1},
	"ionice":      {shortFlags: "t", shortArgs: "cnpP", longFlags: []string{"ignore", "help", "version"}, longArgs: []string{"class", "classdata", "pid", "pgid", "uid"}},
	"taskset":     {shortFlags: "acp", longFlags: []string{"all-tasks", "cpu-list", "pid", "help", "version"}, positionals: 1},
	"numactl":     {shortFlags: "HVs", longFlags: []string{"show", "hardware", "length", "strict", "relative", "all", "balancing", "touch", "dump", "dump-nodes", "localalloc", "help", "version"}, longArgs: []string{"membind", "cpunodebind", "physcpubind", "interleave", "preferred", "preferred-many", "weighted-interleave", "file", "offset", "shmmode", "shmid", "huge", "nodes", "cpus"}},
	"flock":       {kind: launcherFlock, shortFlags: "sxunwEoF", shortArgs: "cw", longFlags: []string{"shared", "exclusive", "unlock", "nonblock", "no-fork", "close", "verbose", "help", "version"}, longArgs: []string{"timeout", "conflict-exit-code", "command"}},
	"unshare":     {shortFlags: "imnpuUfrR", longFlags: []string{"mount", "uts", "ipc", "net", "pid", "user", "cgroup", "time", "fork", "map-root-user", "map-current-user", "kill-child", "mount-proc", "propagation", "setgroups", "keep-caps", "root", "wd", "setuid", "setgid", "help", "version"}},
	"nsenter":     {shortFlags: "aminupCT", shortArgs: "trwSFG", longFlags: []string{"all", "no-fork", "help", "version"}, longArgs: []string{"target", "setuid", "setgid"}, longOptional: []string{"mount", "uts", "ipc", "net", "pid", "cgroup", "time", "root", "wd", "follow-context", "preserve-credentials"}},
	"xargs":       {kind: launcherXargs, shortFlags: "0prt", shortArgs: "IinPLdEas", longFlags: []string{"null", "open-tty", "no-run-if-empty", "verbose", "interactive", "show-limits", "help", "version"}, longArgs: []string{"replace", "max-args", "max-procs", "max-lines", "delimiter", "eof", "arg-file", "max-chars"}},
	"sudo":        {shortFlags: "EHnSkbhisVv", shortArgs: "ugpC", longFlags: []string{"preserve-env", "set-home", "non-interactive", "stdin", "reset-timestamp", "background", "help", "login", "shell", "version", "validate"}, longArgs: []string{"user", "group", "prompt", "close-from"}},
	"doas":        {shortFlags: "nLs", shortArgs: "u"},
	"su":          {kind: launcherScript, shortFlags: "lmps", shortArgs: "cgw", longFlags: []string{"login", "preserve-environment", "help", "version"}, longArgs: []string{"command", "group", "supp-group", "shell"}},
	"find":        {kind: launcherFind},
	"watch":       {kind: launcherScript, shortFlags: "bdgntpxe", shortArgs: "n", longFlags: []string{"beep", "color", "differences", "no-title", "precise", "exec", "help", "version"}, longArgs: []string{"interval"}},
	"script":      {kind: launcherScript, shortFlags: "aeqf", shortArgs: "ctIoO", longFlags: []string{"append", "return", "quiet", "flush", "force", "echo", "help", "version"}, longArgs: []string{"command", "command-limit", "timing", "log-in", "log-out", "log-io"}},
	"systemd-run": {shortFlags: "qtupG", shortArgs: "HP", longFlags: []string{"quiet", "user", "system", "scope", "wait", "collect", "same-dir", "pipe", "pty", "remain-after-exit", "help", "version"}, longArgs: []string{"unit", "description", "property", "working-directory", "setenv", "slice", "service-type", "uid", "gid"}},
	"bash":        {kind: launcherShell},
	"sh":          {kind: launcherShell},
	"dash":        {kind: launcherShell},
	"zsh":         {kind: launcherShell},
	"ksh":         {kind: launcherShell},
	"eval":        {kind: launcherScript},
	"busybox":     {},
	"toybox":      {},
	"time":        {shortFlags: "p", shortArgs: "fop", longFlags: []string{"portability", "verbose", "help", "version"}, longArgs: []string{"format", "output"}},
}

type launcherResult struct {
	words   []string
	static  []bool
	cwd     string
	script  string
	ok      bool
	noExec  bool
	stdin   bool
	replace string
}

func resolveLauncherWords(words []string, static []bool, cwd string) launcherResult {
	result := launcherResult{words: words, static: static, cwd: cwd, ok: true}
	for depth := 0; depth < 16 && len(result.words) > 0; depth++ {
		if !result.static[0] {
			result.ok = false
			return result
		}
		program := programBase(result.words[0])
		spec, found := launcherSpecs[program]
		if !found {
			return result
		}
		if spec.kind == launcherEnv {
			if !resolveEnvWords(&result) {
				result.ok = false
				return result
			}
			continue
		}
		if program == "busybox" || program == "toybox" || program == "builtin" {
			result.words, result.static = result.words[1:], result.static[1:]
			continue
		}
		if program == "eval" {
			if !allStatic(result.static[1:]) {
				result.ok = false
				return result
			}
			result.script = strings.Join(result.words[1:], " ")
			result.words, result.static = nil, nil
			return result
		}
		if spec.kind == launcherShell {
			resolveShellString(&result)
			return result
		}
		if spec.kind == launcherFind {
			resolveFindCommand(&result)
			if result.script != "" || !result.ok || result.noExec {
				return result
			}
			continue
		}
		index, values, ok := launcherOptions(result.words, result.static, spec)
		if !ok {
			result.ok = false
			return result
		}
		if program == "command" && (values["v"] != "" || values["V"] != "") ||
			values["help"] != "" || values["version"] != "" || program == "sudo" && values["h"] != "" {
			result.noExec = true
			result.words, result.static = nil, nil
			return result
		}
		if program == "nice" && index < len(result.words) && result.static[index] &&
			len(result.words[index]) > 1 && result.words[index][0] == '-' && decimalDigits(result.words[index][1:]) {
			index++
		}
		if program == "sudo" && (values["i"] != "" || values["s"] != "") {
			result.ok = false
			return result
		}
		if spec.kind == launcherScript {
			script := values["c"]
			if script == "" {
				script = values["command"]
			}
			if script == "" && program == "watch" {
				if index >= len(result.words) || !allStatic(result.static[index:]) {
					result.ok = false
					return result
				}
				script = strings.Join(result.words[index:], " ")
			}
			if script != "" {
				result.script, result.words, result.static = script, nil, nil
				return result
			}
			if program == "su" || program == "script" {
				result.noExec = true
				result.words, result.static = nil, nil
				return result
			}
		}
		if spec.kind == launcherFlock {
			if script := values["c"]; script != "" {
				result.script, result.words, result.static = script, nil, nil
				return result
			}
			if index >= len(result.words) || !result.static[index] {
				result.ok = false
				return result
			}
			index++ // file or descriptor
			if index < len(result.words) && (result.words[index] == "-c" || result.words[index] == "--command") {
				if index+1 >= len(result.words) || !result.static[index+1] {
					result.ok = false
					return result
				}
				result.script, result.words, result.static = result.words[index+1], nil, nil
				return result
			}
		}
		if spec.kind == launcherXargs {
			result.stdin = true
		}
		for skip := 0; skip < spec.positionals; skip++ {
			if index >= len(result.words) || !result.static[index] {
				result.ok = false
				return result
			}
			index++
		}
		if index >= len(result.words) {
			result.noExec = true
			result.words, result.static = nil, nil
			return result
		}
		result.words, result.static = result.words[index:], result.static[index:]
		if spec.kind == launcherXargs {
			replace := values["I"]
			if replace == "" {
				replace = values["i"]
			}
			if replace == "" {
				replace = values["replace"]
			}
			if replace != "" {
				result.replace = replace
				for i, word := range result.words {
					if strings.Contains(word, replace) {
						result.static[i] = false
					}
				}
			}
		}
	}
	if len(result.words) > 0 {
		result.ok = false
	}
	return result
}

func allStatic(static []bool) bool { return !slices.Contains(static, false) }

func launcherAssignmentPrefix(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return ""
	}
	lit, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return ""
	}
	name, _, assigned := strings.Cut(lit.Value, "=")
	if !assigned || name == "" {
		return ""
	}
	for i, char := range name {
		if char != '_' && (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') &&
			(i == 0 || char < '0' || char > '9') {
			return ""
		}
	}
	return name + "="
}

func decimalDigits(text string) bool {
	if text == "" {
		return false
	}
	for _, char := range text {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func launcherOptions(words []string, static []bool, spec launcherSpec) (int, map[string]string, bool) {
	values := map[string]string{}
	longNames := append(append(slices.Clone(spec.longFlags), spec.longArgs...), spec.longOptional...)
	for i := 1; i < len(words); i++ {
		if !static[i] {
			return i, values, false
		}
		word := words[i]
		if word == "--" {
			return i + 1, values, true
		}
		if word == "-" || !strings.HasPrefix(word, "-") {
			return i, values, true
		}
		if strings.HasPrefix(word, "--") {
			name, value, joined := strings.Cut(word[2:], "=")
			name, unique := longOption(name, longNames)
			if !unique || name == "" {
				return i, values, false
			}
			if slices.Contains(spec.longArgs, name) {
				if !joined {
					i++
					if i >= len(words) || !static[i] {
						return i, values, false
					}
					value = words[i]
				}
				if value == "" {
					return i, values, false
				}
			} else if slices.Contains(spec.longOptional, name) {
				if !joined {
					value = "1"
				}
			} else if joined {
				return i, values, false
			} else {
				value = "1"
			}
			values[name] = value
			continue
		}
		for j := 1; j < len(word); j++ {
			flag := word[j]
			if strings.ContainsRune(spec.shortArgs, rune(flag)) {
				value := word[j+1:]
				if value == "" {
					i++
					if i >= len(words) || !static[i] {
						return i, values, false
					}
					value = words[i]
				}
				if value == "" {
					return i, values, false
				}
				values[string(flag)] = value
				break
			}
			if !strings.ContainsRune(spec.shortFlags, rune(flag)) {
				return i, values, false
			}
			values[string(flag)] = "1"
		}
	}
	return len(words), values, true
}

func resolveEnvWords(result *launcherResult) bool {
	words, static := result.words, result.static
	options := []string{"ignore-environment", "null", "debug", "unset", "chdir", "argv0", "split-string", "block-signal", "default-signal", "ignore-signal", "list-signal-handling", "help", "version"}
	i := 1
	for i < len(words) {
		if !static[i] {
			if strings.HasSuffix(words[i], "=") {
				i++
				continue
			}
			return false
		}
		word := words[i]
		if word == "--" {
			i++
			break
		}
		if strings.HasPrefix(word, "--") {
			name, value, joined := strings.Cut(word[2:], "=")
			name, unique := longOption(name, options)
			if !unique || name == "" {
				return false
			}
			switch name {
			case "unset", "chdir", "argv0", "split-string":
				if !joined {
					i++
					if i >= len(words) || !static[i] {
						return false
					}
					value = words[i]
				}
				if value == "" {
					return false
				}
			case "block-signal", "default-signal", "ignore-signal":
				// The signal list is an optional joined value.
			default:
				if joined {
					return false
				}
			}
			switch name {
			case "chdir":
				result.cwd = OperandPath(value, result.cwd)
			case "split-string":
				split, ok := splitLauncherString(value)
				if !ok {
					return false
				}
				result.words = append(split, words[i+1:]...)
				result.static = append(makeStatic(len(split)), static[i+1:]...)
				return true
			case "null", "help", "version":
				result.noExec = true
				result.words, result.static = nil, nil
				return true
			}
			i++
			continue
		}
		if len(word) > 1 && word[0] == '-' {
			for j := 1; j < len(word); j++ {
				flag := word[j]
				switch flag {
				case 'i', 'v':
				case '0':
					result.noExec = true
					result.words, result.static = nil, nil
					return true
				case 'u', 'C', 'a', 'S':
					value := word[j+1:]
					if value == "" {
						i++
						if i >= len(words) || !static[i] {
							return false
						}
						value = words[i]
					}
					if value == "" {
						return false
					}
					if flag == 'C' {
						result.cwd = OperandPath(value, result.cwd)
					}
					if flag == 'S' {
						split, ok := splitLauncherString(value)
						if !ok {
							return false
						}
						result.words = append(split, words[i+1:]...)
						result.static = append(makeStatic(len(split)), static[i+1:]...)
						return true
					}
					j = len(word)
				default:
					return false
				}
			}
			i++
			continue
		}
		if strings.Contains(word, "=") {
			i++
			continue
		}
		break
	}
	result.words, result.static = words[i:], static[i:]
	if len(result.words) == 0 {
		result.noExec = true
	}
	return true
}

func splitLauncherString(value string) ([]string, bool) {
	file, ok := parseShell(value)
	if !ok || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return nil, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return nil, false
	}
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		words[i], ok = StaticWord(arg, "")
		if !ok {
			return nil, false
		}
	}
	return words, true
}

func resolveShellString(result *launcherResult) {
	words, static := result.words, result.static
	for i := 1; i < len(words); i++ {
		if !static[i] {
			result.ok = false
			return
		}
		word := words[i]
		if word == "--" {
			return
		}
		if strings.HasPrefix(word, "-") && !strings.HasPrefix(word, "--") {
			for j := 1; j < len(word); j++ {
				switch word[j] {
				case 'l', 'x', 'e':
				case 'o', 'O':
					if j+1 == len(word) {
						i++
						if i >= len(words) || !static[i] {
							result.ok = false
							return
						}
					}
					j = len(word)
				case 'c':
					if j+1 < len(word) {
						result.script = word[j+1:]
					} else {
						i++
						if i >= len(words) || !static[i] {
							result.ok = false
							return
						}
						result.script = words[i]
					}
					result.words, result.static = nil, nil
					return
				default:
					result.ok = false
					return
				}
			}
			continue
		}
		return // script file or standard input
	}
	result.noExec = true
}

func resolveFindCommand(result *launcherResult) {
	var searchPaths []string
	for i := 1; i < len(result.words); i++ {
		switch result.words[i] {
		case "-exec", "-execdir", "-ok", "-okdir":
			start := i + 1
			for i = start; i < len(result.words); i++ {
				if !result.static[i] {
					result.ok = false
					return
				}
				if result.words[i] == ";" || result.words[i] == "+" {
					break
				}
			}
			if i >= len(result.words) || i == start {
				result.ok = false
				return
			}
			result.words, result.static = result.words[start:i], result.static[start:i]
			for j, word := range result.words {
				if !strings.Contains(word, "{}") {
					continue
				}
				if len(searchPaths) == 1 {
					result.words[j] = strings.ReplaceAll(word, "{}", searchPaths[0])
					result.static[j] = true
				} else {
					result.static[j] = false
				}
			}
			return
		}
		if !strings.HasPrefix(result.words[i], "-") && result.static[i] && len(searchPaths) == i-1 {
			searchPaths = append(searchPaths, result.words[i])
		}
	}
	result.words, result.static, result.noExec = nil, nil, true
}

type shellScriptContext struct {
	file    *syntax.File
	cwd     string
	source  string
	handled map[int]bool
}

func shellAnalysisScripts(command, cwd, home string) ([]shellScriptContext, bool) {
	file, ok := parseShell(command)
	if !ok {
		return nil, true
	}
	queue := []shellScriptContext{{file: file, cwd: cwd, source: command}}
	unknown := false
	for i := 0; i < len(queue); i++ {
		if i >= 16 {
			return queue[:i], true
		}
		if queue[i].handled == nil {
			queue[i].handled = map[int]bool{}
		}
		context := queue[i]
		syntax.Walk(context.file, func(node syntax.Node) bool {
			if pipe, ok := node.(*syntax.BinaryCmd); ok && pipe.Op == syntax.Pipe {
				appendXargsInputScript(&queue, pipe, context, home)
			}
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			words := make([]string, len(call.Args))
			static := make([]bool, len(call.Args))
			for j, arg := range call.Args {
				words[j], static[j] = StaticWord(arg, home)
				if !static[j] {
					words[j] = launcherAssignmentPrefix(arg)
				}
			}
			if !static[0] {
				return true
			}
			_, known := launcherSpecs[programBase(words[0])]
			if !known {
				return true
			}
			result := resolveLauncherWords(words, static, context.cwd)
			if !result.ok {
				unknown = true
				return true
			}
			if result.script != "" {
				inner, parsed := parseShell(result.script)
				if !parsed {
					unknown = true
				} else {
					queue = append(queue, shellScriptContext{file: inner, cwd: result.cwd, source: result.script})
				}
			}
			return true
		})
	}
	return queue, unknown
}

func appendXargsInputScript(queue *[]shellScriptContext, pipe *syntax.BinaryCmd, context shellScriptContext, home string) {
	if pipe.X == nil || pipe.Y == nil {
		return
	}
	code, known := literalProducerCode(pipe.X, context.source, home)
	if !known {
		return
	}
	values := strings.Fields(code)
	if len(values) != 1 {
		return
	}
	call, ok := pipe.Y.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	words := make([]string, len(call.Args))
	static := make([]bool, len(call.Args))
	for j, arg := range call.Args {
		words[j], static[j] = StaticWord(arg, home)
	}
	if !static[0] || programBase(words[0]) != "xargs" {
		return
	}
	result := resolveLauncherWords(words, static, context.cwd)
	if !result.ok || result.replace == "" || len(result.words) == 0 {
		return
	}
	for j, word := range result.words {
		result.words[j] = strings.ReplaceAll(word, result.replace, values[0])
		result.static[j] = true
	}
	if !allStatic(result.static) {
		return
	}
	var quoted []string
	for _, word := range result.words {
		quoted = append(quoted, "'"+strings.ReplaceAll(word, "'", "'\\''")+"'")
	}
	source := strings.Join(quoted, " ")
	inner, parsed := parseShell(source)
	if parsed {
		*queue = append(*queue, shellScriptContext{file: inner, cwd: result.cwd, source: source})
		context.handled[int(call.Pos().Offset())] = true
	}
}

// LauncherAnalysisUnknown reports a prefix whose child cannot be read from
// the command text.
func LauncherAnalysisUnknown(command, cwd, home string) bool {
	_, unknown := shellAnalysisScripts(command, cwd, home)
	return unknown
}

// NestedShellDynamicWrite reports an unresolved redirect in a literal child
// shell script.
func NestedShellDynamicWrite(command, cwd, home string) bool {
	contexts, _ := shellAnalysisScripts(command, cwd, home)
	if len(contexts) < 2 {
		return false
	}
	for _, context := range contexts[1:] {
		for _, occurrence := range shellWriteOccurrences(context.file, context.cwd, home) {
			if !occurrence.Static {
				return true
			}
		}
	}
	return false
}
