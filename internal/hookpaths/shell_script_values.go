// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shellScriptWordStates records exact values before each straight-line call.
// A call that may change the shell environment clears the later bindings.
func shellScriptWordStates(file *syntax.File, home, cwd string) shellWordStateMap {
	states := shellWordStateMap{}
	vars := shellVariables{}
	for _, stmt := range file.Stmts {
		if stmt == nil || stmt.Background || stmt.Negated {
			clear(vars)
			continue
		}
		if decl, ok := stmt.Cmd.(*syntax.DeclClause); ok {
			if decl.Variant == nil || decl.Variant.Value == "nameref" {
				clear(vars)
				continue
			}
			for _, assign := range decl.Args {
				if assign.Name == nil || !shellIdentifier(assign.Name.Value) {
					clear(vars)
					break
				}
				if !assign.Naked {
					shellApplyAssignments([]*syntax.Assign{assign}, home, vars, shellVariablePoison{})
				}
			}
			continue
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok {
			clear(vars)
			continue
		}
		if len(call.Args) == 0 {
			shellApplyAssignments(call.Assigns, home, vars, shellVariablePoison{})
			continue
		}
		for _, arg := range call.Args {
			states[int(arg.Pos().Offset())] = vars.clone()
		}
		program, known := shellStaticWordWithKnownCalls(call.Args[0], home, cwd, vars, shellVariablePoison{})
		if !known {
			clear(vars)
			continue
		}
		switch programBase(program) {
		case "printf":
			shellScriptPrintfBinding(call, home, cwd, vars)
		case "export", "readonly", "declare", "typeset", "local":
			shellScriptNamedBindings(call, home, cwd, vars)
		case "eval":
			words := shellScriptExactWords(call.Args[1:], home, cwd, vars)
			clear(vars)
			if words != nil {
				if values, ok := shellEvalAssignmentText(strings.Join(words, " "), home); ok {
					for name, value := range values {
						vars[name] = value
					}
				}
			}
		case "source", ".", "read", "mapfile", "readarray", "getopts", "set", "shift", "trap":
			clear(vars)
		}
	}
	return states
}

func shellScriptExactWords(words []*syntax.Word, home, cwd string, vars shellVariables) []string {
	values := make([]string, len(words))
	for i, word := range words {
		value, ok := shellStaticWordWithKnownCalls(word, home, cwd, vars, shellVariablePoison{})
		if !ok {
			return nil
		}
		values[i] = value
	}
	return values
}

func shellScriptPrintfBinding(call *syntax.CallExpr, home, cwd string, vars shellVariables) {
	if len(call.Args) < 3 {
		return
	}
	option, ok := shellStaticWordWithKnownCalls(call.Args[1], home, cwd, vars, shellVariablePoison{})
	if !ok {
		clear(vars)
		return
	}
	if option != "-v" {
		return
	}
	name, ok := shellStaticWordWithKnownCalls(call.Args[2], home, cwd, vars, shellVariablePoison{})
	if !ok || !shellIdentifier(name) {
		clear(vars)
		return
	}
	words := shellScriptExactWords(call.Args[3:], home, cwd, vars)
	if len(words) == 0 {
		delete(vars, name)
		return
	}
	value, ok := shellPrintfValue(words[0], words[1:])
	if !ok {
		delete(vars, name)
		return
	}
	vars[name] = value
}

func shellScriptNamedBindings(call *syntax.CallExpr, home, cwd string, vars shellVariables) {
	for _, arg := range call.Args[1:] {
		word, ok := shellStaticWordWithKnownCalls(arg, home, cwd, vars, shellVariablePoison{})
		if !ok {
			clear(vars)
			return
		}
		if strings.HasPrefix(word, "-") {
			continue
		}
		name, value, assigned := strings.Cut(word, "=")
		if !shellIdentifier(name) || name == "HOME" {
			clear(vars)
			return
		}
		if assigned {
			vars[name] = value
		}
	}
}
