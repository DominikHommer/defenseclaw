// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func shellLiteralEvalAssignments(call *syntax.CallExpr, home string) (map[string]string, bool) {
	if call == nil || len(call.Args) < 2 {
		return nil, false
	}
	words := make([]string, 0, len(call.Args)-1)
	for _, word := range call.Args[1:] {
		value, ok := StaticWord(word, home)
		if !ok {
			return nil, false
		}
		words = append(words, value)
	}
	script := strings.Join(words, " ")
	return shellEvalAssignmentText(script, home)
}

func shellEvalAssignmentText(script, home string) (map[string]string, bool) {
	budget := newShellAnalysisBudget()
	file, ok, _ := parseShellWithinBudget(script, &budget)
	if !ok || len(file.Stmts) == 0 {
		return nil, false
	}
	values := map[string]string{}
	for _, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(stmt.Redirs) != 0 || len(call.Args) != 0 || len(call.Assigns) == 0 {
			return nil, false
		}
		for _, assign := range call.Assigns {
			name := shellAssignName(assign)
			if name == "" || assign.Append || assign.Naked || assign.Index != nil || assign.Array != nil || assign.Value == nil {
				return nil, false
			}
			value, ok := StaticWord(assign.Value, home)
			if !ok {
				return nil, false
			}
			values[name] = value
		}
	}
	return values, true
}
