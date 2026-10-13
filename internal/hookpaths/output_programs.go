// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"
)

type outputProgramGrammar struct {
	shortValues []string
	longValues  []string
	readFlags   []string
	position    int
	createOnly  bool
}

// Each entry names the option or positional operand that carries an output
// file. A negative position means the program has no output positional.
var outputProgramGrammars = map[string]outputProgramGrammar{
	"sort":       {shortValues: []string{"o"}, longValues: []string{"output"}, position: -1},
	"wget":       {shortValues: []string{"O"}, longValues: []string{"output-document"}, position: -1},
	"curl":       {shortValues: []string{"o"}, longValues: []string{"output"}, position: -1},
	"ssh-keygen": {shortValues: []string{"f"}, readFlags: []string{"-l", "-y", "-L", "-e", "-i"}, position: -1},
	"git":        {longValues: []string{"output", "file"}, position: -1},
	"sqlite3":    {position: 0},
	"openssl":    {shortValues: []string{"out"}, position: -1},
	"gpg":        {shortValues: []string{"o"}, longValues: []string{"output"}, position: -1},
	"script":     {position: -2},
	"strace":     {shortValues: []string{"o"}, longValues: []string{"output"}, position: -1},
	"ltrace":     {shortValues: []string{"o"}, position: -1},
	"time":       {shortValues: []string{"o"}, longValues: []string{"output"}, position: -1},
	"zstd":       {shortValues: []string{"o"}, longValues: []string{"output"}, position: -1},
	"xz":         {shortValues: []string{"o"}, position: -1},
	"bzip2":      {shortValues: []string{"o"}, position: -1},
	"tar":        {shortValues: []string{"f"}, longValues: []string{"file"}, position: -1, createOnly: true},
	"gtar":       {shortValues: []string{"f"}, longValues: []string{"file"}, position: -1, createOnly: true},
	"bsdtar":     {shortValues: []string{"f"}, longValues: []string{"file"}, position: -1, createOnly: true},
	"zip":        {position: 0},
	"7z":         {position: 0},
	"7za":        {position: 0},
	"split":      {position: 1},
}

func outputProgramFiles(program string, args []string, cwd string) []string {
	grammar, ok := outputProgramGrammars[program]
	if !ok {
		return nil
	}
	for _, arg := range args {
		for _, readFlag := range grammar.readFlags {
			if arg == readFlag {
				return nil
			}
		}
	}
	if grammar.createOnly {
		create := false
		for _, arg := range args {
			if arg == "--create" || arg == "-c" || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "c") {
				create = true
			}
		}
		if !create {
			return nil
		}
	}
	if program == "7z" || program == "7za" {
		if len(args) == 0 || args[0] != "a" {
			return nil
		}
		args = args[1:]
	}
	if program == "git" {
		for len(args) >= 2 && args[0] == "-C" {
			cwd = OperandPath(args[1], cwd)
			args = args[2:]
		}
		if len(args) == 0 {
			return nil
		}
		if args[0] == "diff" {
			grammar.longValues = []string{"output"}
		} else if args[0] == "config" {
			readOnly := false
			for _, arg := range args[1:] {
				if arg == "--get" || arg == "--get-all" || arg == "--list" || arg == "--name-only" {
					readOnly = true
				}
			}
			if readOnly {
				return nil
			}
			grammar.longValues = []string{"file"}
		} else {
			return nil
		}
		args = args[1:]
	}
	var outputs, positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "--") {
			name, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			if selected, matched := longOption(name, grammar.longValues); matched && selected != "" {
				if !hasValue && i+1 < len(args) {
					i++
					value = args[i]
				}
				if value != "" {
					outputs = append(outputs, value)
				}
				continue
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if program == "script" && (arg == "-c" || arg == "--command" || arg == "-t") {
				if i+1 < len(args) {
					i++
				}
				continue
			}
			for _, name := range grammar.shortValues {
				prefix := "-" + name
				if arg == prefix {
					if i+1 < len(args) {
						i++
						outputs = append(outputs, args[i])
					}
					goto next
				}
				if len(name) == 1 && strings.HasPrefix(arg, prefix) && len(arg) > len(prefix) {
					outputs = append(outputs, strings.TrimPrefix(arg, prefix))
					goto next
				}
			}
			if grammar.createOnly && len(arg) > 2 && !strings.HasPrefix(arg, "--") {
				if at := strings.IndexByte(arg[1:], 'f'); at >= 0 {
					trailing := arg[at+2:]
					if trailing == "" && i+1 < len(args) {
						i++
						trailing = args[i]
					}
					if trailing != "" {
						outputs = append(outputs, trailing)
					}
				}
			}
			continue
		}
		positionals = append(positionals, arg)
	next:
	}
	if grammar.position >= 0 && grammar.position < len(positionals) {
		name := positionals[grammar.position]
		if program == "split" {
			outputs = append(outputs, name+"aa", name+"00")
		} else {
			outputs = append(outputs, name)
		}
	}
	if grammar.position == -2 && len(positionals) > 0 {
		outputs = append(outputs, positionals[len(positionals)-1])
	}
	if program == "curl" {
		remote := false
		for _, arg := range args {
			if arg == "-O" || arg == "--remote-name" {
				remote = true
			}
		}
		if remote {
			for _, input := range positionals {
				if name := filepath.Base(strings.SplitN(input, "?", 2)[0]); name != "" && name != "." {
					outputs = append(outputs, name)
				}
			}
		}
	}
	var paths []string
	for _, name := range outputs {
		if name == "" || name == "-" || strings.HasPrefix(name, "-") {
			continue
		}
		paths = append(paths, OperandPath(name, cwd))
	}
	return paths
}
