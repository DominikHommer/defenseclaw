// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// SimpleCommand is one command of a shell action, with the directory in
// which it runs. Its text is independently suitable for Analyze.
type SimpleCommand struct {
	Text string
	CWD  string
	// EvaluationFailure is "limit" or "parse" when no complete per-command
	// view can be produced. Callers must refuse the action in either case.
	EvaluationFailure string
}

type simpleShellState struct {
	cwd  string
	vars map[string]string
}

const (
	maxSimpleStates      = 32
	maxSimpleEvaluations = 512
)

func (s simpleShellState) clone() simpleShellState {
	copy := simpleShellState{cwd: s.cwd, vars: make(map[string]string, len(s.vars))}
	for name, value := range s.vars {
		copy.vars[name] = value
	}
	return copy
}

// SimpleCommands flattens an action with the full parser used by the hook
// command class rule. Every returned command is judged on its own, in
// addition to the original action. A plain single command needs no second
// pass. Ordinary assignments and known home or local variable expansions
// are resolved; a subshell or pipeline stage has its own shell state.
func SimpleCommands(input Input, facts Facts) []SimpleCommand {
	if facts.Parse.Dialect != DialectPOSIX {
		return nil
	}
	source := input.Command
	if source == "" {
		_, capture := analyzeWithRedirectTargets(input, "")
		source = capture.source
	}
	if len(source) > maxCommandBytes {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	if source == "" {
		return nil
	}
	if !strings.ContainsAny(source, ";&|(){}<>\n`$=!") {
		return nil
	}
	parts, reduced, ok := sequenceStatementDetails(source, true, true)
	if !ok {
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	if len(parts) == 0 {
		return nil
	}
	if len(parts) > maxStatementsAlone {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	if !reduced && len(parts) == 1 {
		file, parsed := shellparse.Parse(parts[0].text)
		if !parsed || len(file.Stmts) != 1 {
			return nil
		}
		stmt := file.Stmts[0]
		call, _ := stmt.Cmd.(*syntax.CallExpr)
		prefix := call != nil && len(call.Assigns) != 0 && len(call.Args) != 0
		duplication := slices.ContainsFunc(stmt.Redirs, func(redirect *syntax.Redirect) bool {
			return redirect.Op == syntax.DplIn || redirect.Op == syntax.DplOut
		})
		if !prefix && !duplication {
			return nil
		}
	}
	home, _ := normalizeActiveHome(input.ActiveHome)
	initialVars := map[string]string{"HOME": home}
	if filepath.IsAbs(input.CWD) {
		initialVars["PWD"] = filepath.Clean(input.CWD)
	}
	states := map[string][]simpleShellState{
		"0": {{cwd: input.CWD, vars: initialVars}},
	}
	result := make([]SimpleCommand, 0, len(parts))
	changed := reduced || len(parts) != 1
	previousScope := "0"
	for _, part := range parts {
		// A conditional or loop body runs in its parent's shell when selected.
		// Keep both its resulting state and the path that skipped the body.
		for previousScope != part.scope && !strings.HasPrefix(part.scope, previousScope+"/") {
			index := strings.LastIndexByte(previousScope, '/')
			if index < 0 {
				return []SimpleCommand{{EvaluationFailure: "parse"}}
			}
			parent := previousScope[:index]
			if previousScope[index+1] == 'c' {
				states[parent] = uniqueSimpleStates(append(states[parent], states[previousScope]...))
				if len(states[parent]) > maxSimpleStates {
					return []SimpleCommand{{EvaluationFailure: "limit"}}
				}
			}
			previousScope = parent
		}
		previousScope = part.scope
		variants, present := states[part.scope]
		if !present {
			parent := part.scope
			for {
				index := strings.LastIndexByte(parent, '/')
				if index < 0 {
					return []SimpleCommand{{EvaluationFailure: "parse"}}
				}
				parent = parent[:index]
				if inherited, ok := states[parent]; ok {
					for _, state := range inherited {
						variants = append(variants, state.clone())
					}
					break
				}
			}
		}
		file, parsed := shellparse.Parse(part.text)
		if !parsed || len(file.Stmts) != 1 {
			return []SimpleCommand{{EvaluationFailure: "parse"}}
		}
		stmt := file.Stmts[0]
		nextVariants := make([]simpleShellState, 0, len(variants))
		emitted := make(map[SimpleCommand]bool)
		for _, prior := range variants {
			state := prior.clone()
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) == 0 && len(call.Assigns) != 0 && len(stmt.Redirs) == 0 {
				updateSimpleVariables(state.vars, call.Assigns)
				changed = true
				nextVariants = append(nextVariants, state)
				continue
			}
			text := part.text
			effective := state.vars
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Assigns) != 0 && len(call.Args) != 0 {
				effective = state.clone().vars
				updateSimpleVariables(effective, call.Assigns)
				// The policy facts are the command's argv. Keep prefixes
				// that can change executable resolution: dropping PATH from
				// `PATH=/missing $'rm' -rf /` would invent a runnable rm.
				if !simplePrefixChangesResolution(call.Assigns) {
					start := int(call.Args[0].Pos().Offset())
					end := int(call.Pos().Offset())
					if start <= end || start > len(text) {
						return []SimpleCommand{{EvaluationFailure: "parse"}}
					}
					text = text[start:]
					changed = true
				}
			}
			if resolved, ok := simpleResolvedVariables(text, effective); ok {
				text = resolved
				changed = true
			}
			if stripped, ok := withoutDescriptorDuplications(text); ok {
				text = stripped
				changed = true
			}
			if strings.TrimSpace(text) == "" {
				return []SimpleCommand{{EvaluationFailure: "parse"}}
			}
			command := SimpleCommand{Text: text, CWD: state.cwd}
			if !emitted[command] {
				result = append(result, command)
				emitted[command] = true
				if len(result) > maxSimpleEvaluations {
					return []SimpleCommand{{EvaluationFailure: "limit"}}
				}
			}
			nextCWD, changedDirectory := simpleCommandNextCWD(text, state.cwd, effective)
			if changedDirectory {
				if state.cwd != "" {
					state.vars["OLDPWD"] = state.cwd
				} else {
					delete(state.vars, "OLDPWD")
				}
				if nextCWD != "" {
					state.vars["PWD"] = nextCWD
				} else {
					delete(state.vars, "PWD")
				}
			}
			state.cwd = nextCWD
			nextVariants = append(nextVariants, state)
		}
		states[part.scope] = uniqueSimpleStates(nextVariants)
		if len(states[part.scope]) > maxSimpleStates {
			return []SimpleCommand{{EvaluationFailure: "limit"}}
		}
	}
	if !changed {
		return nil
	}
	return result
}

func simplePrefixChangesResolution(assigns []*syntax.Assign) bool {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil {
			continue
		}
		switch assign.Name.Value {
		case "PATH", "IFS", "CDPATH", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS":
			return true
		}
		if strings.HasPrefix(assign.Name.Value, "LD_") ||
			strings.HasPrefix(assign.Name.Value, "DYLD_") {
			return true
		}
	}
	return false
}

func uniqueSimpleStates(states []simpleShellState) []simpleShellState {
	result := make([]simpleShellState, 0, len(states))
	for _, state := range states {
		if !slices.ContainsFunc(result, func(previous simpleShellState) bool {
			return previous.cwd == state.cwd && maps.Equal(previous.vars, state.vars)
		}) {
			result = append(result, state)
		}
	}
	return result
}

func updateSimpleVariables(vars map[string]string, assigns []*syntax.Assign) {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil || assign.Index != nil || assign.Array != nil {
			continue
		}
		name := assign.Name.Value
		if assign.Value == nil {
			vars[name] = ""
		} else if value, known := simpleStaticWord(assign.Value, vars); known {
			vars[name] = value
		} else {
			delete(vars, name)
		}
	}
}

func simpleStaticWord(word *syntax.Word, vars map[string]string) (string, bool) {
	if word == nil {
		return "", false
	}
	safe := true
	syntax.Walk(word, func(node syntax.Node) bool {
		switch part := node.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				safe = false
			}
		case *syntax.ParamExp:
			if part.Param == nil {
				safe = false
				return false
			}
			_, known := vars[part.Param.Value]
			if !known || part.Excl || part.Length || part.Width || part.IsSet || part.Index != nil ||
				part.Slice != nil || part.Repl != nil || part.Names != 0 || part.Exp != nil ||
				part.Flags != nil || part.NestedParam != nil || len(part.Modifiers) != 0 {
				safe = false
			}
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ExtGlob, *syntax.BraceExp:
			safe = false
		}
		return safe
	})
	if !safe {
		return "", false
	}
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	slices.Sort(names)
	env := make([]string, 0, len(names))
	for _, name := range names {
		env = append(env, name+"="+vars[name])
	}
	fields, err := expand.Fields(&expand.Config{Env: expand.ListEnviron(env...)}, word)
	if err != nil || len(fields) != 1 || strings.ContainsAny(fields[0], "\x00\r\n") {
		return "", false
	}
	return fields[0], true
}

func simpleResolvedVariables(source string, vars map[string]string) (string, bool) {
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return "", false
	}
	type replacement struct {
		start, end int
		text       string
	}
	var replacements []replacement
	syntax.Walk(file, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok &&
			(redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc) {
			return false
		}
		word, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		hasParam := false
		hasTilde := false
		if len(word.Parts) != 0 {
			if lit, ok := word.Parts[0].(*syntax.Lit); ok {
				hasTilde = lit.Value == "~" || strings.HasPrefix(lit.Value, "~/")
			}
		}
		syntax.Walk(word, func(part syntax.Node) bool {
			if _, ok := part.(*syntax.ParamExp); ok {
				hasParam = true
			}
			return true
		})
		if !hasParam && !hasTilde {
			return false
		}
		value, known := simpleStaticWord(word, vars)
		if !known {
			return false
		}
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start >= 0 && end > start && end <= len(source) {
			replacements = append(replacements, replacement{start, end,
				"'" + strings.ReplaceAll(value, "'", "'\\''") + "'"})
		}
		return false
	})
	if len(replacements) == 0 {
		return "", false
	}
	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		source = source[:r.start] + r.text + source[r.end:]
	}
	return source, true
}

func simpleCommandNextCWD(source, cwd string, vars map[string]string) (string, bool) {
	file, parsed := shellparse.Parse(source)
	if !parsed || len(file.Stmts) != 1 {
		return cwd, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 || call.Args[0].Lit() != "cd" {
		return cwd, false
	}
	arg := 1
	if arg < len(call.Args) && call.Args[arg].Lit() == "--" {
		arg++
	}
	if arg == len(call.Args) {
		return vars["HOME"], true
	}
	if arg+1 != len(call.Args) {
		return "", true
	}
	dir, known := simpleStaticWord(call.Args[arg], vars)
	if !known || dir == "" {
		return "", true
	}
	if dir == "-" {
		return vars["OLDPWD"], true
	}
	if filepath.IsAbs(dir) {
		return filepath.Clean(dir), true
	}
	if cwd == "" {
		return "", true
	}
	return filepath.Clean(filepath.Join(cwd, dir)), true
}
