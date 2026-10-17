// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// trustedPOSIXHomeLiteral is an ActiveHome that reads as the same path when
// written unquoted into a POSIX shell word: no whitespace, quoting,
// expansion, glob or tilde characters. A Windows drive home (C:/Users/alice)
// qualifies too, as in posixShellHome (GAP-0912).
var trustedPOSIXHomeLiteral = regexp.MustCompile(`^(?:[A-Za-z]:)?/[A-Za-z0-9._@+/-]*$`)

// trustedPOSIXHomeRewrite has home-anchored operands replaced by ActiveHome.
type trustedPOSIXHomeRewrite struct {
	source string
	// tildeOperands maps each rewritten operand to its original home-path
	// spelling (including HOME parameter forms).
	tildeOperands map[string]string
}

// rewriteTrustedPOSIXHomeTilde replaces home-anchored operands of simple
// commands in a plain pipeline, and "~/..." file redirect
// targets (`echo x >> ~/.ssh/id_ed25519`, GAP-1666) with the trusted
// ActiveHome, the one expansion ActionFacts already resolves from it (see
// projectTrustedPOSIXHomeCatRead).
//
// The shell expands that tilde to $HOME, which ActiveHome is for the
// identity running the action, so the result is exact only while nothing in
// the input can have changed HOME first. The rewrite is therefore limited to
// commands with no assignments or other HOME mentions. Pipeline/list members
// have no redirects or dynamic words; the lone-command redirect handling is
// retained. "~user" forms and command names are never rewritten. The caller
// keeps the rewrite only when its parse is complete.
func rewriteTrustedPOSIXHomeTilde(source, activeHome string) (trustedPOSIXHomeRewrite, bool) {
	if !trustedPOSIXHomeLiteral.MatchString(activeHome) ||
		(!strings.Contains(source, "~") && !strings.Contains(source, "HOME")) {
		return trustedPOSIXHomeRewrite{}, false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(strings.NewReader(source), "")
	if err != nil || len(file.Stmts) == 0 {
		return trustedPOSIXHomeRewrite{}, false
	}
	binary, isBinary := file.Stmts[0].Cmd.(*syntax.BinaryCmd)
	colonAnd := isBinary && binary.Op == syntax.AndStmt
	if len(file.Stmts) != 1 || trustedHomeInertGroup(file.Stmts[0]) || colonAnd {
		var ok bool
		source, ok = normalizeTrustedHomeInertList(file)
		if !ok {
			return trustedPOSIXHomeRewrite{}, false
		}
		file, err = syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(source), "")
		if err != nil {
			return trustedPOSIXHomeRewrite{}, false
		}
	}
	var words []*syntax.Word
	var collect func(*syntax.Stmt, bool) bool
	collect = func(stmt *syntax.Stmt, compound bool) bool {
		if stmt.Negated || stmt.Background || stmt.Coprocess {
			return false
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			if len(stmt.Redirs) != 0 || cmd.Op != syntax.Pipe {
				return false
			}
			return collect(cmd.X, true) && collect(cmd.Y, true)
		case *syntax.CallExpr:
			if len(cmd.Assigns) != 0 || len(cmd.Args) == 0 ||
				(compound && len(stmt.Redirs) != 0) {
				return false
			}
			for _, word := range cmd.Args {
				if !staticHomeRewriteWord(word) {
					return false
				}
			}
			words = append(words, cmd.Args[1:]...)
			for _, redirect := range stmt.Redirs {
				switch redirect.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.ClbOut:
					if literal, ok := firstLiteral(redirect.Word); ok && strings.HasPrefix(literal.Value, "~/") {
						words = append(words, redirect.Word)
					}
				default:
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	targets := 0
	for _, stmt := range file.Stmts {
		if trustedHomeInertColon(stmt) {
			continue
		}
		if !collect(stmt, false) {
			return trustedPOSIXHomeRewrite{}, false
		}
		targets++
	}
	if targets != 1 {
		return trustedPOSIXHomeRewrite{}, false
	}
	sort.Slice(words, func(i, j int) bool { return words[i].Pos().Offset() < words[j].Pos().Offset() })
	var out strings.Builder
	last := 0
	rewrite := trustedPOSIXHomeRewrite{tildeOperands: map[string]string{}}
	for _, word := range words {
		literal, ok := firstLiteral(word)
		if !ok || (literal.Value != "~" && !strings.HasPrefix(literal.Value, "~/")) {
			if suffix, anchored := homeAnchoredLiteralWord(word); anchored &&
				plainHomeRewriteWord(word) {
				start, end := int(word.Pos().Offset()), int(word.End().Offset())
				if start < last || end > len(source) {
					return trustedPOSIXHomeRewrite{}, false
				}
				out.WriteString(source[last:start])
				out.WriteString(activeHome + suffix)
				last = end
				rewrite.tildeOperands[activeHome+suffix] = source[start:end]
			}
			continue
		}
		offset := int(literal.Pos().Offset())
		if offset < last || offset >= len(source) || source[offset] != '~' {
			return trustedPOSIXHomeRewrite{}, false
		}
		out.WriteString(source[last:offset])
		out.WriteString(activeHome)
		last = offset + 1
		// A word that is one plain literal re-parses to exactly home+rest;
		// its path facts get the "~" spelling back.
		if len(word.Parts) == 1 && !strings.ContainsAny(literal.Value, `\*?[`) {
			rewrite.tildeOperands[activeHome+literal.Value[1:]] = literal.Value
		}
	}
	if last == 0 {
		return trustedPOSIXHomeRewrite{}, false
	}
	out.WriteString(source[last:])
	// A separate HOME mention can change what the rewritten operands name.
	if strings.Contains(out.String(), "HOME") {
		return trustedPOSIXHomeRewrite{}, false
	}
	rewrite.source = out.String()
	return rewrite, true
}

// Only a colon with no arguments can be discarded as an inert list member.
// Static redirects remain in the normalized source so their writes are still
// analyzed. Dynamic redirects cannot be proven safe by this rewrite.
func trustedHomeInertColon(stmt *syntax.Stmt) bool {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 1 {
		return false
	}
	program := projectPOSIXWord(call.Args[0])
	if program.Expands || program.Value != ":" && program.Value != "true" {
		return false
	}
	for _, redirect := range stmt.Redirs {
		if target := projectPOSIXWord(redirect.Word); target.Expands {
			return false
		}
	}
	return true
}

func trustedHomeInertGroup(stmt *syntax.Stmt) bool {
	if stmt == nil || len(stmt.Redirs) != 0 || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false
	}
	switch group := stmt.Cmd.(type) {
	case *syntax.Block:
		return len(group.Stmts) == 1 && trustedHomeInertColon(group.Stmts[0]) && len(group.Stmts[0].Redirs) == 0
	case *syntax.Subshell:
		return len(group.Stmts) == 1 && trustedHomeInertColon(group.Stmts[0]) && len(group.Stmts[0].Redirs) == 0
	default:
		return false
	}
}

// A colon succeeds unconditionally, so a colon AND target executes exactly
// like a list. Braces and subshells containing only a colon have no state to
// carry into the target command. Keep every other construct out of this proof.
func normalizeTrustedHomeInertList(file *syntax.File) (string, bool) {
	var parts []string
	targets := 0
	printStmt := func(stmt *syntax.Stmt) (string, bool) {
		var buf bytes.Buffer
		if err := syntax.NewPrinter().Print(&buf, stmt); err != nil {
			return "", false
		}
		return buf.String(), true
	}
	for _, stmt := range file.Stmts {
		if trustedHomeInertGroup(stmt) {
			parts = append(parts, "true")
			continue
		}
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok &&
			binary.Op == syntax.AndStmt && len(stmt.Redirs) == 0 &&
			trustedHomeInertColon(binary.X) && len(binary.X.Redirs) == 0 {
			stmt = binary.Y
			parts = append(parts, "true")
		}
		if !trustedHomeInertColon(stmt) {
			if _, ok := stmt.Cmd.(*syntax.CallExpr); !ok ||
				stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
				return "", false
			}
			targets++
		}
		segment, ok := printStmt(stmt)
		if !ok {
			return "", false
		}
		if trustedHomeInertColon(stmt) && strings.HasPrefix(segment, ":") {
			segment = "true" + segment[1:]
		}
		parts = append(parts, segment)
	}
	if targets != 1 {
		return "", false
	}
	return strings.Join(parts, "; "), true
}

func normalizeTrustedHomeInertListSource(source string) (string, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(source), "")
	if err != nil || file == nil || len(file.Stmts) == 0 {
		return "", false
	}
	return normalizeTrustedHomeInertList(file)
}

func staticHomeRewriteWord(word *syntax.Word) bool {
	if plainHomeRewriteWord(word) {
		return true
	}
	for _, part := range word.Parts {
		switch part.(type) {
		case *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
		default:
			return false
		}
	}
	return true
}

func plainHomeRewriteWord(word *syntax.Word) bool {
	if _, ok := homeAnchoredLiteralWord(word); !ok {
		return false
	}
	for _, part := range word.Parts {
		switch part.(type) {
		case *syntax.Lit, *syntax.ParamExp:
		default:
			return false
		}
	}
	return true
}

func firstLiteral(word *syntax.Word) (*syntax.Lit, bool) {
	if word == nil || len(word.Parts) == 0 {
		return nil, false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	return literal, ok
}

// respellTrustedPOSIXHomeTilde gives the path facts of rewritten operands
// back their "~" spelling (Value and Normalized), as a partial parse of the
// original text records them, while Resolved keeps the ActiveHome path, so
// rules that match a home path by its spelling keep matching it. A static
// redirect target of those commands gets the same spelling, so it still
// names its path fact: the owners that tie a redirect to the path it writes
// compare the two values, and without it a lone `echo k >> ~/.ssh/
// authorized_keys` lost its finding while the absolute and chained forms
// kept theirs (GAP-0892, GAP-0894, GAP-0896).
func respellTrustedPOSIXHomeTilde(facts *Facts, commandIDs map[int64]struct{}, tildeOperands map[string]string) {
	if facts == nil || len(tildeOperands) == 0 {
		return
	}
	for index := range facts.Commands {
		command := &facts.Commands[index]
		if _, ok := commandIDs[command.ID]; !ok || command.Dialect != DialectPOSIX {
			continue
		}
		for redirectIndex := range command.Redirects {
			redirect := &command.Redirects[redirectIndex]
			if spelling, ok := tildeOperands[redirect.Target]; ok && !redirect.Expands {
				redirect.Target = spelling
			}
		}
	}
	for index := range facts.Paths {
		path := &facts.Paths[index]
		if _, ok := commandIDs[path.CommandID]; !ok || path.Flavor != PathFlavorPOSIX {
			continue
		}
		spelling, ok := tildeOperands[path.Value]
		if !ok || path.Resolved != path.Value {
			continue
		}
		path.Value = spelling
		path.Normalized = spelling
		path.Absolute = false
	}
}
