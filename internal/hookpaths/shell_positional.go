// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"bytes"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func shellClearPositionals(vars shellVariables) {
	for i := 1; i <= 9; i++ {
		delete(vars, strconv.Itoa(i))
	}
}

func shellApplyPositionalCall(program string, operands []*syntax.Word, home string, vars shellVariables, poison shellVariablePoison) {
	switch program {
	case "set":
		start := -1
		for i := 0; i < len(operands); i++ {
			operand := operands[i]
			value, ok := staticShellWordWithVars(operand, home, vars, poison)
			if !ok {
				shellClearPositionals(vars)
				return
			}
			if value == "--" {
				start = i + 1
				break
			}
			if value == "-o" || value == "+o" {
				if i+1 >= len(operands) {
					return
				}
				i++
				continue
			}
			if strings.HasPrefix(value, "-") || strings.HasPrefix(value, "+") {
				if len(value) < 2 || strings.Trim(value[1:], "abefhkmnptuvxBCEHPT") != "" {
					shellClearPositionals(vars)
					return
				}
				continue
			}
			start = i
			break
		}
		if start < 0 {
			return
		}
		values := make([]string, 0, len(operands)-start)
		known := make([]bool, 0, len(operands)-start)
		for _, operand := range operands[start:] {
			value, ok := staticShellWordWithVars(operand, home, vars, poison)
			values = append(values, value)
			known = append(known, ok)
		}
		shellClearPositionals(vars)
		for i, value := range values {
			if i >= 9 {
				break
			}
			if known[i] {
				vars[strconv.Itoa(i+1)] = value
			}
		}
	case "shift":
		count := 1
		if len(operands) > 1 {
			shellClearPositionals(vars)
			return
		}
		if len(operands) == 1 {
			value, ok := staticShellWordWithVars(operands[0], home, vars, poison)
			if !ok {
				shellClearPositionals(vars)
				return
			}
			var err error
			count, err = strconv.Atoi(value)
			if err != nil || count < 0 {
				shellClearPositionals(vars)
				return
			}
		}
		old := vars.clone()
		shellClearPositionals(vars)
		for i := 1; i <= 9; i++ {
			if value, ok := old[strconv.Itoa(i+count)]; ok {
				vars[strconv.Itoa(i)] = value
			}
		}
	case "eval", "source", ".":
		shellClearPositionals(vars)
	}
}

// shellPositionalScript substitutes exact arguments before analysing shell text.
func shellPositionalScript(source string, args []string, static []bool) (string, bool) {
	if !allStatic(static) {
		return "", false
	}
	file, ok := parseShell(source)
	if !ok {
		return "", false
	}
	kept, ok := shellRewritePositionalStatements(file.Stmts, &args)
	if !ok {
		return "", false
	}
	file.Stmts = kept
	var rendered bytes.Buffer
	if err := syntax.NewPrinter().Print(&rendered, file); err != nil {
		return "", false
	}
	return rendered.String(), true
}

func shellRewritePositionalStatements(stmts []*syntax.Stmt, args *[]string) ([]*syntax.Stmt, bool) {
	kept := make([]*syntax.Stmt, 0, len(stmts))
	for _, stmt := range stmts {
		if stmt == nil {
			continue
		}
		if block, ok := stmt.Cmd.(*syntax.Block); ok {
			children, valid := shellRewritePositionalStatements(block.Stmts, args)
			if !valid {
				return nil, false
			}
			block.Stmts = children
			kept = append(kept, stmt)
			continue
		}
		if subshell, ok := stmt.Cmd.(*syntax.Subshell); ok {
			childArgs := append([]string(nil), (*args)...)
			children, valid := shellRewritePositionalStatements(subshell.Stmts, &childArgs)
			if !valid {
				return nil, false
			}
			subshell.Stmts = children
			kept = append(kept, stmt)
			continue
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Assigns) == 0 && len(call.Args) != 0 && len(stmt.Redirs) == 0 {
			program := call.Args[0].Lit()
			if program == "shift" {
				count := 1
				if len(call.Args) == 2 {
					var err error
					count, err = strconv.Atoi(call.Args[1].Lit())
					if err != nil {
						return nil, false
					}
				} else if len(call.Args) != 1 {
					return nil, false
				}
				if count < 0 || count >= len(*args) {
					return nil, false
				}
				*args = append((*args)[:1:1], (*args)[1+count:]...)
				continue
			}
			if program == "set" && len(call.Args) > 1 {
				separator := -1
				for i, word := range call.Args[1:] {
					if word.Lit() == "--" {
						separator = i + 2
						break
					}
				}
				if separator >= 0 {
					next := []string{(*args)[0]}
					for _, word := range call.Args[separator:] {
						value, ok := StaticWord(word, "")
						if !ok {
							return nil, false
						}
						next = append(next, value)
					}
					*args = next
				}
			}
		}
		valid := true
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
							if len(*args) != 2 {
								valid = false
								continue
							}
							index = 1
						} else if err != nil || index < 0 {
							continue
						}
						if index >= len(*args) {
							valid = false
							continue
						}
						if quoted {
							parts[i] = &syntax.Lit{Value: (*args)[index]}
						} else {
							parts[i] = &syntax.SglQuoted{Value: (*args)[index]}
						}
					}
				}
				return parts
			}
			word.Parts = replace(word.Parts, false)
			return true
		})
		if !valid {
			return nil, false
		}
		kept = append(kept, stmt)
	}
	return kept, true
}
