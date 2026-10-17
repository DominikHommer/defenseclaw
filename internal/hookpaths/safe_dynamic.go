// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SafeDynamicKey records a narrow client-side proof for one computed redirect
// whose path cannot name an existing protected file. The gateway checks the
// command shape again before accepting this proof.
const SafeDynamicKey = "\x00safe-dynamic"

// SafeDynamicRedirect recognizes a fresh mktemp target or a numeric filename
// under a directory whose existing entries were all resolved. It accepts only
// a straight assignment followed by a plain writer, or a lone plain writer.
func SafeDynamicRedirect(command, cwd, home string) bool {
	return safeDynamicRedirect(command, cwd, home, true)
}

// SafeDynamicRedirectShape rechecks the syntax on a managed gateway that
// cannot inspect the protected user home. It still requires the hook proof.
func SafeDynamicRedirectShape(command, cwd, home string) bool {
	return safeDynamicRedirect(command, cwd, home, false)
}

func safeDynamicRedirect(command, cwd, home string, verifyFS bool) bool {
	if !filepath.IsAbs(cwd) || !filepath.IsAbs(home) {
		return false
	}
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) == 0 || len(file.Stmts) > 2 {
		return false
	}
	variable, kind := "", ""
	writer := file.Stmts[0]
	if len(file.Stmts) == 2 {
		variable, kind = safeDynamicAssignment(file.Stmts[0], home)
		if kind == "" {
			return false
		}
		writer = file.Stmts[1]
	}
	if writer.Background || writer.Negated {
		return false
	}
	call, ok := writer.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return false
	}
	program, ok := StaticWord(call.Args[0], home)
	if !ok || (program != "printf" && program != "echo" && program != "cat") {
		return false
	}
	for _, arg := range call.Args[1:] {
		if _, ok := StaticWord(arg, home); !ok {
			return false
		}
	}
	var output *syntax.Word
	for _, redir := range writer.Redirs {
		switch redir.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob:
			if output != nil || redir.Word == nil {
				return false
			}
			output = redir.Word
		case syntax.Hdoc, syntax.DashHdoc:
			// Data for cat, not another output target.
		default:
			return false
		}
	}
	if output == nil {
		return false
	}
	parts := output.Parts
	if len(parts) != 1 {
		return false
	}
	quoted, ok := parts[0].(*syntax.DblQuoted)
	if !ok {
		return false
	}
	if kind == "mktemp-file" || kind == "mktemp-dir" {
		if len(quoted.Parts) == 0 || len(quoted.Parts) > 2 {
			return false
		}
		param, ok := quoted.Parts[0].(*syntax.ParamExp)
		if !ok || !safePlainParam(param, variable) {
			return false
		}
		if kind == "mktemp-file" {
			return len(quoted.Parts) == 1
		}
		if len(quoted.Parts) != 2 {
			return false
		}
		leaf, ok := quoted.Parts[1].(*syntax.Lit)
		if !ok || !strings.HasPrefix(leaf.Value, "/") ||
			strings.Contains(leaf.Value[1:], "/") || leaf.Value[1:] == "" ||
			leaf.Value[1:] == "." || leaf.Value[1:] == ".." {
			return false
		}
		if !verifyFS {
			return true
		}
		// If mktemp fails, the shell still attempts /leaf. Check that path.
		fallback, ok := ResolveWriteTarget(leaf.Value)
		if !ok {
			return false
		}
		resolved, ok := newProtectedFiles(home).target(fallback)
		return ok && !newProtectedFiles(home).has(resolved)
	}
	if len(quoted.Parts) != 3 {
		return false
	}
	prefix, firstOK := quoted.Parts[0].(*syntax.Lit)
	param, secondOK := quoted.Parts[1].(*syntax.ParamExp)
	suffix, thirdOK := quoted.Parts[2].(*syntax.Lit)
	if !firstOK || !secondOK || !thirdOK || !strings.HasSuffix(suffix.Value, ".log") ||
		strings.Contains(suffix.Value, "/") {
		return false
	}
	if kind == "" {
		if param.Param == nil || param.Param.Value != "RANDOM" && param.Param.Value != "$" {
			return false
		}
		if !safePlainParam(param, param.Param.Value) {
			return false
		}
	} else if kind != "date-digits" || !safePlainParam(param, variable) {
		return false
	}
	dir := filepath.Dir(prefix.Value)
	if dir == "." || strings.ContainsAny(dir, "$`*?[]") {
		return false
	}
	for _, component := range strings.Split(filepath.ToSlash(dir), "/") {
		if component == ".." {
			return false
		}
	}
	return !verifyFS || safeNumericDirectory(OperandPath(dir, cwd), home)
}

func safePlainParam(param *syntax.ParamExp, name string) bool {
	return param != nil && param.Param != nil && param.Param.Value == name &&
		param.Index == nil && param.Exp == nil && param.Flags == nil &&
		!param.Excl && !param.Length && !param.Width && !param.IsSet &&
		param.NestedParam == nil && len(param.Modifiers) == 0 &&
		param.Slice == nil && param.Repl == nil && param.Names == 0
}

func safeDynamicAssignment(stmt *syntax.Stmt, home string) (variable, kind string) {
	if stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return "", ""
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return "", ""
	}
	assign := call.Assigns[0]
	variable = shellAssignName(assign)
	if variable == "" || assign.Value == nil {
		return "", ""
	}
	parts := assign.Value.Parts
	if len(parts) == 1 {
		if quoted, ok := parts[0].(*syntax.DblQuoted); ok {
			parts = quoted.Parts
		}
	}
	if len(parts) != 1 {
		return "", ""
	}
	sub, ok := parts[0].(*syntax.CmdSubst)
	if !ok || len(sub.Stmts) != 1 || len(sub.Stmts[0].Redirs) != 0 ||
		sub.Stmts[0].Background || sub.Stmts[0].Negated {
		return "", ""
	}
	inner, ok := sub.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(inner.Assigns) != 0 || len(inner.Args) == 0 {
		return "", ""
	}
	words, ok := shellStaticWords(inner.Args, home)
	if !ok {
		return "", ""
	}
	switch {
	case len(words) == 1 && words[0] == "mktemp":
		return variable, "mktemp-file"
	case len(words) == 2 && words[0] == "mktemp" && words[1] == "-d":
		return variable, "mktemp-dir"
	case len(words) == 2 && words[0] == "date" && (words[1] == "+%s" || words[1] == "+%Y%m%d"):
		return variable, "date-digits"
	}
	return "", ""
}

func safeNumericDirectory(path, home string) bool {
	dir, ok := ResolveWriteTarget(path)
	if !ok {
		return false
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > MaxWriteTargets {
		return false
	}
	protected := newProtectedFiles(home)
	for _, entry := range entries {
		resolved, ok := ResolveWriteTarget(filepath.Join(dir, entry.Name()))
		if !ok {
			return false
		}
		resolved, ok = protected.target(resolved)
		if !ok || protected.has(resolved) {
			return false
		}
	}
	return true
}
