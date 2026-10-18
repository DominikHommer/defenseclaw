// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shellPositionalWriteOperands resolves a small straight-line shell subset
// with set --, shift, and function-local arguments. A failed proof contributes
// no target: the general dynamic resolver then remains fail-closed.
func shellPositionalWriteOperands(file *syntax.File, cwd, home string) ([]string, bool) {
	if file == nil || !filepath.IsAbs(cwd) {
		return nil, false
	}
	state := positionalWriteState{
		cwd: cwd, home: home, functions: make(map[string]*syntax.FuncDecl),
		seen: make(map[string]bool),
	}
	if !state.walkList(file.Stmts, 0) || !state.sawPositional {
		return nil, false
	}
	return state.paths, true
}

type positionalWriteState struct {
	cwd, home     string
	args          []string
	functions     map[string]*syntax.FuncDecl
	paths         []string
	seen          map[string]bool
	steps         *int
	sawPositional bool
}

func (s *positionalWriteState) walkList(stmts []*syntax.Stmt, depth int) bool {
	if depth > 16 || len(stmts) > MaxWriteTargets {
		return false
	}
	for _, stmt := range stmts {
		if !s.walk(stmt, depth) {
			return false
		}
	}
	return true
}

func (s *positionalWriteState) walk(stmt *syntax.Stmt, depth int) bool {
	if stmt == nil || stmt.Background || stmt.Negated {
		return false
	}
	if s.steps == nil {
		s.steps = new(int)
	}
	*s.steps++
	if *s.steps > MaxWriteTargets {
		return false
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.FuncDecl:
		if len(stmt.Redirs) != 0 || cmd.Name == nil || cmd.Body == nil {
			return false
		}
		if strings.Contains(" set shift echo printf cat ", " "+cmd.Name.Value+" ") {
			return false
		}
		s.functions[cmd.Name.Value] = cmd
		return true
	case *syntax.Subshell:
		if len(stmt.Redirs) != 0 {
			return false
		}
		child := *s
		child.args = append([]string(nil), s.args...)
		if !child.walkList(cmd.Stmts, depth+1) {
			return false
		}
		s.paths, s.sawPositional = child.paths, child.sawPositional
		return true
	case *syntax.Block:
		if len(stmt.Redirs) != 0 {
			return false
		}
		return s.walkList(cmd.Stmts, depth+1)
	case *syntax.CallExpr:
		if len(cmd.Assigns) != 0 || len(cmd.Args) == 0 {
			return false
		}
		program, ok := StaticWord(cmd.Args[0], s.home)
		if !ok {
			return false
		}
		switch program {
		case "set":
			if len(stmt.Redirs) != 0 || len(cmd.Args) < 2 {
				return false
			}
			separator, ok := StaticWord(cmd.Args[1], s.home)
			if !ok || separator != "--" || len(cmd.Args)-2 > MaxWriteTargets {
				return false
			}
			next := make([]string, 0, len(cmd.Args)-2)
			for _, word := range cmd.Args[2:] {
				value, ok := s.word(word)
				if !ok || !safePositionalValue(value) {
					return false
				}
				next = append(next, value)
			}
			s.args = next
			return true
		case "shift":
			if len(stmt.Redirs) != 0 || len(cmd.Args) > 2 {
				return false
			}
			count := 1
			if len(cmd.Args) == 2 {
				value, ok := StaticWord(cmd.Args[1], s.home)
				if !ok {
					return false
				}
				var err error
				count, err = strconv.Atoi(value)
				if err != nil {
					return false
				}
			}
			if count < 0 || count > len(s.args) {
				return false
			}
			s.args = s.args[count:]
			return true
		case "echo", "printf", "cat":
			for _, word := range cmd.Args[1:] {
				if _, ok := StaticWord(word, s.home); !ok {
					return false
				}
			}
			return s.redirects(stmt.Redirs)
		default:
			function := s.functions[program]
			if function == nil || len(stmt.Redirs) != 0 || depth >= 16 {
				return false
			}
			old := s.args
			args := make([]string, 0, len(cmd.Args)-1)
			for _, word := range cmd.Args[1:] {
				value, ok := s.word(word)
				if !ok || !safePositionalValue(value) {
					return false
				}
				args = append(args, value)
			}
			s.args = args
			ok = s.walk(function.Body, depth+1)
			s.args = old
			return ok
		}
	default:
		return false
	}
}

func (s *positionalWriteState) redirects(redirs []*syntax.Redirect) bool {
	for _, redirect := range redirs {
		if redirect.Word == nil {
			return false
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		default:
			return false
		}
		if _, ok := StaticWord(redirect.Word, s.home); ok {
			continue // Already handled by ShellWriteOperands.
		}
		value, ok := s.word(redirect.Word)
		if !ok || !safePositionalValue(value) {
			return false
		}
		path := OperandPath(value, s.cwd)
		if !s.seen[path] {
			s.seen[path] = true
			s.paths = append(s.paths, path)
			if len(s.paths) > MaxWriteTargets {
				return false
			}
		}
		s.sawPositional = true
	}
	return true
}

func (s *positionalWriteState) word(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	var out strings.Builder
	var parts func([]syntax.WordPart) bool
	parts = func(items []syntax.WordPart) bool {
		for _, item := range items {
			switch part := item.(type) {
			case *syntax.Lit:
				out.WriteString(part.Value)
			case *syntax.SglQuoted:
				out.WriteString(part.Value)
			case *syntax.DblQuoted:
				if !parts(part.Parts) {
					return false
				}
			case *syntax.ParamExp:
				if part.Param == nil || !safePlainParam(part, part.Param.Value) {
					return false
				}
				switch part.Param.Value {
				case "HOME":
					out.WriteString(s.home)
				case "PWD":
					out.WriteString(s.cwd)
				default:
					index, err := strconv.Atoi(part.Param.Value)
					if err != nil || index < 1 || index > len(s.args) {
						return false
					}
					out.WriteString(s.args[index-1])
				}
			default:
				return false
			}
		}
		return true
	}
	if !parts(word.Parts) {
		return "", false
	}
	return out.String(), true
}

func safePositionalValue(value string) bool {
	return value != "" && len(value) <= MaxWriteTargetPathBytes &&
		!strings.ContainsAny(value, "\x00\r\n\t *?[]")
}
