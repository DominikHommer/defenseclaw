// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"bytes"
	"strconv"

	"mvdan.cc/sh/v3/syntax"
)

// shellPositionalScript substitutes exact arguments before analysing shell text.
func shellPositionalScript(source string, args []string, static []bool) (string, bool) {
	if !allStatic(static) {
		return "", false
	}
	file, ok := parseShell(source)
	if !ok {
		return "", false
	}
	var kept []*syntax.Stmt
	valid := true
	for _, stmt := range file.Stmts {
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Assigns) == 0 && len(call.Args) > 0 &&
			call.Args[0].Lit() == "shift" && len(stmt.Redirs) == 0 {
			count := 1
			if len(call.Args) == 2 {
				var err error
				count, err = strconv.Atoi(call.Args[1].Lit())
				if err != nil {
					return "", false
				}
			} else if len(call.Args) != 1 {
				return "", false
			}
			if count < 0 || count >= len(args) {
				return "", false
			}
			args = append(args[:1:1], args[1+count:]...)
			continue
		}
		syntax.Walk(stmt, func(node syntax.Node) bool {
			word, ok := node.(*syntax.Word)
			if !ok {
				return true
			}
			var replace func([]syntax.WordPart, bool) []syntax.WordPart
			replace = func(parts []syntax.WordPart, quoted bool) []syntax.WordPart {
				for i, part := range parts {
					switch part := part.(type) {
					case *syntax.DblQuoted:
						part.Parts = replace(part.Parts, true)
					case *syntax.ParamExp:
						if part.Param == nil || part.Exp != nil || part.Index != nil {
							continue
						}
						name := part.Param.Value
						index, err := strconv.Atoi(name)
						if name == "@" || name == "*" {
							if len(args) != 2 {
								valid = false
								continue
							}
							index = 1
						} else if err != nil || index < 0 {
							continue
						}
						if index >= len(args) {
							valid = false
							continue
						}
						if quoted {
							parts[i] = &syntax.Lit{Value: args[index]}
						} else {
							parts[i] = &syntax.SglQuoted{Value: args[index]}
						}
					}
				}
				return parts
			}
			word.Parts = replace(word.Parts, false)
			return true
		})
		kept = append(kept, stmt)
	}
	if !valid {
		return "", false
	}
	file.Stmts = kept
	var rendered bytes.Buffer
	if err := syntax.NewPrinter().Print(&rendered, file); err != nil {
		return "", false
	}
	return rendered.String(), true
}
