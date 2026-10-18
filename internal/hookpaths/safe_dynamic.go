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
	if !ok {
		return false
	}
	return safeDynamicRedirectFile(file, cwd, home, verifyFS)
}

func safeDynamicRedirectFile(file *syntax.File, cwd, home string, verifyFS bool) bool {
	if file == nil || !filepath.IsAbs(cwd) || !filepath.IsAbs(home) {
		return false
	}
	if safeLargeLiteralLoop(file, cwd, home, verifyFS) {
		return true
	}
	if len(file.Stmts) == 0 || len(file.Stmts) > 3 {
		return false
	}
	variable, kind := "", ""
	writer := file.Stmts[0]
	if len(file.Stmts) >= 2 {
		variable, kind = safeDynamicAssignment(file.Stmts[0], cwd, home, verifyFS)
		if kind == "" {
			return false
		}
		writer = file.Stmts[len(file.Stmts)-1]
		if len(file.Stmts) == 3 && (kind != "mktemp-dir" ||
			!safeExitCleanupTrap(file.Stmts[1], variable, home)) {
			return false
		}
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
	if len(parts) == 1 {
		if quoted, ok := parts[0].(*syntax.DblQuoted); ok {
			parts = quoted.Parts
		} else if !safeUnquotedDefaultMktemp(file, kind, home, verifyFS) {
			return false
		}
	} else if !safeUnquotedDefaultMktemp(file, kind, home, verifyFS) {
		return false
	}
	if kind == "" && len(parts) > 0 {
		if sub, ok := parts[0].(*syntax.CmdSubst); ok {
			kind = safeInlineMktemp(sub, cwd, home, verifyFS)
		}
	}
	if kind == "mktemp-file" || kind == "mktemp-dir" {
		if len(parts) == 0 || len(parts) > 2 {
			return false
		}
		switch first := parts[0].(type) {
		case *syntax.ParamExp:
			if !safePlainParam(first, variable) {
				return false
			}
		case *syntax.CmdSubst:
			if variable != "" || safeInlineMktemp(first, cwd, home, verifyFS) != kind {
				return false
			}
		default:
			return false
		}
		if kind == "mktemp-file" {
			return len(parts) == 1
		}
		if len(parts) != 2 {
			return false
		}
		leaf, ok := parts[1].(*syntax.Lit)
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
	if len(parts) != 3 {
		return false
	}
	prefix, firstOK := parts[0].(*syntax.Lit)
	suffix, thirdOK := parts[2].(*syntax.Lit)
	if !firstOK || !thirdOK || !strings.HasSuffix(suffix.Value, ".log") ||
		strings.Contains(suffix.Value, "/") {
		return false
	}
	if kind == "" {
		switch part := parts[1].(type) {
		case *syntax.ParamExp:
			if part.Param == nil || part.Param.Value != "RANDOM" && part.Param.Value != "$" ||
				!safePlainParam(part, part.Param.Value) {
				return false
			}
		case *syntax.CmdSubst:
			if !safeDateDigitsSubstitution(part, home) {
				return false
			}
		default:
			return false
		}
	} else {
		param, ok := parts[1].(*syntax.ParamExp)
		if !ok || kind != "date-digits" || !safePlainParam(param, variable) {
			return false
		}
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

func safeExitCleanupTrap(stmt *syntax.Stmt, variable, home string) bool {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 3 {
		return false
	}
	words, ok := shellStaticWords(call.Args, home)
	if !ok || words[0] != "trap" || (words[2] != "EXIT" && words[2] != "0") {
		return false
	}
	return words[1] == `rm -rf $`+variable || words[1] == `rm -rf "$`+variable+`"`
}

// An unquoted $tmp/a remains one redirect word only for the default mktemp
// directory form and an environment that cannot split or glob its pathname.
func safeUnquotedDefaultMktemp(file *syntax.File, kind, home string, verifyFS bool) bool {
	if kind != "mktemp-dir" || file == nil || len(file.Stmts) < 2 {
		return false
	}
	outer, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(outer.Args) != 0 || len(outer.Assigns) != 1 || outer.Assigns[0].Value == nil {
		return false
	}
	parts := outer.Assigns[0].Value.Parts
	if len(parts) == 1 {
		if quoted, ok := parts[0].(*syntax.DblQuoted); ok {
			parts = quoted.Parts
		}
	}
	if len(parts) != 1 {
		return false
	}
	sub, ok := parts[0].(*syntax.CmdSubst)
	if !ok || len(sub.Stmts) != 1 {
		return false
	}
	inner, ok := sub.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(inner.Assigns) != 0 {
		return false
	}
	words, ok := shellStaticWords(inner.Args, home)
	if !ok || len(words) != 2 || words[0] != "mktemp" || words[1] != "-d" {
		return false
	}
	if !verifyFS {
		return true
	}
	ifs := os.Getenv("IFS")
	if ifs != "" && ifs != " \t\n" {
		return false
	}
	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		tmpdir = os.TempDir()
	}
	return filepath.IsAbs(tmpdir) && !strings.ContainsAny(tmpdir, " \t\r\n*?[]\x00")
}

func safeInlineMktemp(sub *syntax.CmdSubst, cwd, home string, verifyFS bool) string {
	if sub == nil || len(sub.Stmts) != 1 || sub.Stmts[0].Background ||
		sub.Stmts[0].Negated || len(sub.Stmts[0].Redirs) != 0 {
		return ""
	}
	call, ok := sub.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 || len(call.Args) > 3 {
		return ""
	}
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		value, ok := staticShellWordWithVars(arg, home, shellVariables{"PWD": cwd}, shellVariablePoison{})
		if !ok {
			return ""
		}
		words[i] = value
	}
	switch {
	case len(words) == 1 && words[0] == "mktemp":
		return "mktemp-file"
	case len(words) == 2 && words[0] == "mktemp" && words[1] == "-d":
		return "mktemp-dir"
	case len(words) == 2 && words[0] == "mktemp" && safeMktempTemplate(words[1], cwd, home, verifyFS):
		return "mktemp-file"
	case len(words) == 3 && words[0] == "mktemp" && words[1] == "-d" &&
		safeMktempTemplate(words[2], cwd, home, verifyFS):
		return "mktemp-dir"
	}
	return ""
}

// A large literal loop can contain more exact targets than the hook header
// permits. Check every combination locally, then carry one bounded proof for
// the single writer. The gateway verifies the same restricted syntax before
// trusting that proof from the user's hook.
const maxSafeLiteralLoopTargets = 4096

func safeLargeLiteralLoop(file *syntax.File, cwd, home string, verifyFS bool) bool {
	if len(file.Stmts) != 1 {
		return false
	}
	type dimension struct {
		name   string
		values []string
	}
	var dimensions []dimension
	stmt := file.Stmts[0]
	product := 1
	for len(dimensions) < 2 {
		clause, ok := stmt.Cmd.(*syntax.ForClause)
		if !ok {
			break
		}
		iter, ok := clause.Loop.(*syntax.WordIter)
		if !ok || clause.Select || clause.Braces || iter.Name == nil ||
			!shellIdentifier(iter.Name.Value) || len(iter.Items) == 0 || len(clause.Do) != 1 ||
			stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
			return false
		}
		for _, prior := range dimensions {
			if prior.name == iter.Name.Value {
				return false
			}
		}
		if len(iter.Items) > maxSafeLiteralLoopTargets/product {
			return false
		}
		values := make([]string, 0, len(iter.Items))
		for _, item := range iter.Items {
			value, ok := StaticWord(item, home)
			if !ok || value == "" || strings.ContainsAny(value, "*?[]{}$`\x00\r\n") {
				return false
			}
			values = append(values, value)
		}
		product *= len(values)
		dimensions = append(dimensions, dimension{name: iter.Name.Value, values: values})
		stmt = clause.Do[0]
	}
	if product <= MaxWriteTargets || len(dimensions) == 0 || stmt.Background || stmt.Negated ||
		len(stmt.Redirs) != 1 || stmt.Redirs[0].Word == nil {
		return false
	}
	if _, nested := stmt.Cmd.(*syntax.ForClause); nested {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
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
	switch stmt.Redirs[0].Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob:
	default:
		return false
	}
	word := stmt.Redirs[0].Word
	if len(word.Parts) != 1 {
		return false
	}
	quoted, ok := word.Parts[0].(*syntax.DblQuoted)
	if !ok || len(quoted.Parts) < 2 {
		return false
	}
	first, ok := quoted.Parts[0].(*syntax.Lit)
	if !ok {
		return false
	}
	prefixDir := filepath.Dir(first.Value)
	if prefixDir == "." || prefixDir == string(filepath.Separator) ||
		strings.ContainsAny(prefixDir, "*?[]{}$`\x00\r\n") {
		return false
	}
	prefix := OperandPath(prefixDir, cwd)
	if rest, within := cutPathPrefix(prefix, cwd); !within || rest == "" {
		return false
	}
	var protected protectedFiles
	if verifyFS {
		physical, ok := ResolveWriteTarget(prefix)
		if !ok {
			return false
		}
		info, err := os.Stat(physical)
		if err != nil || !info.IsDir() {
			return false
		}
		protected = newProtectedFiles(home)
		for _, target := range ProtectedAuthorizedKeysPaths(home) {
			resolved, ok := ResolveWriteTarget(target)
			if !ok {
				return false
			}
			if _, within := cutPathPrefix(resolved, physical); within {
				return false
			}
		}
	}
	var check func(int, shellVariables) bool
	check = func(index int, vars shellVariables) bool {
		if index == len(dimensions) {
			name, ok := staticShellWordWithVars(word, home, vars, shellVariablePoison{})
			if !ok || name == "" || len(name) > MaxWriteTargetPathBytes {
				return false
			}
			path := OperandPath(name, cwd)
			if rest, within := cutPathPrefix(path, prefix); !within || rest == "" {
				return false
			}
			if !verifyFS {
				return true
			}
			resolved, ok := ResolveWriteTarget(path)
			if !ok {
				return false
			}
			resolved, ok = protected.target(resolved)
			return ok && !protected.has(resolved)
		}
		dimension := dimensions[index]
		for _, value := range dimension.values {
			vars[dimension.name] = value
			if !check(index+1, vars) {
				return false
			}
		}
		return true
	}
	return check(0, shellVariables{})
}

func safeDateDigitsSubstitution(sub *syntax.CmdSubst, home string) bool {
	if sub == nil || len(sub.Stmts) != 1 {
		return false
	}
	stmt := sub.Stmts[0]
	if stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 2 {
		return false
	}
	program, programOK := StaticWord(call.Args[0], home)
	format, formatOK := StaticWord(call.Args[1], home)
	return programOK && formatOK && program == "date" &&
		(format == "+%s" || format == "+%Y%m%d")
}

func safePlainParam(param *syntax.ParamExp, name string) bool {
	return param != nil && param.Param != nil && param.Param.Value == name &&
		param.Index == nil && param.Exp == nil && param.Flags == nil &&
		!param.Excl && !param.Length && !param.Width && !param.IsSet &&
		param.NestedParam == nil && len(param.Modifiers) == 0 &&
		param.Slice == nil && param.Repl == nil && param.Names == 0
}

func safeDynamicAssignment(stmt *syntax.Stmt, cwd, home string, verifyFS bool) (variable, kind string) {
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
	words := make([]string, len(inner.Args))
	for i, arg := range inner.Args {
		value, ok := staticShellWordWithVars(arg, home, shellVariables{"PWD": cwd}, shellVariablePoison{})
		if !ok {
			return "", ""
		}
		words[i] = value
	}
	switch {
	case len(words) == 1 && words[0] == "mktemp":
		return variable, "mktemp-file"
	case len(words) == 2 && words[0] == "mktemp" && words[1] == "-d":
		return variable, "mktemp-dir"
	case len(words) == 2 && words[0] == "mktemp" &&
		safeMktempTemplate(words[1], cwd, home, verifyFS):
		return variable, "mktemp-file"
	case len(words) == 3 && words[0] == "mktemp" && words[1] == "-d" &&
		safeMktempTemplate(words[2], cwd, home, verifyFS):
		return variable, "mktemp-dir"
	case len(words) == 2 && words[0] == "date" && (words[1] == "+%s" || words[1] == "+%Y%m%d"):
		return variable, "date-digits"
	}
	return "", ""
}

// A successful mktemp creates a fresh entry, so no pre-existing protected
// file or symlink can occupy it. Keep the template under a resolved directory
// that does not contain a protected file; a failed mktemp is checked by the
// redirect's separate fallback path.
func safeMktempTemplate(template, cwd, home string, verifyFS bool) bool {
	if template == "" || strings.HasPrefix(template, "-") ||
		!strings.HasSuffix(filepath.Base(template), "XXXXXX") ||
		strings.ContainsAny(template, "\x00\r\n") {
		return false
	}
	directory := filepath.Dir(OperandPath(template, cwd))
	if !filepath.IsAbs(directory) {
		return false
	}
	if !verifyFS {
		return true
	}
	physical, ok := ResolveWriteTarget(directory)
	if !ok {
		return false
	}
	info, err := os.Stat(physical)
	if err != nil || !info.IsDir() {
		return false
	}
	for _, protected := range ProtectedAuthorizedKeysPaths(home) {
		resolved, ok := ResolveWriteTarget(protected)
		if !ok || physical == resolved || strings.HasPrefix(resolved, physical+string(filepath.Separator)) {
			return false
		}
	}
	return true
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
