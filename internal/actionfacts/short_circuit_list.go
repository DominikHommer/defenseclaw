// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ShortCircuitListReduction returns a complete view of a partial POSIX
// action with && or || lists, read as if every command of each list runs.
// facts must be Analyze(input).
//
// A block stops the whole tool call before any of it runs, so a command that
// runs only when the one before it succeeds (&&) or fails (||) is judged as
// if it runs: a rule that blocks `a; b` also blocks `a && b` and `a || b`.
// The view is the analysis of a twin of the command in which each && or ||
// list is the sequence of its commands, one statement per line. It has every
// command of the action and every fact they own; it differs from the action
// only in that every command is certain to run and the parse is complete, so
// a caller may count a semantic result on it, match or not, for an
// expression that reads neither (semantic.Program.ListReductionSafe).
//
// The view is unavailable unless every statement of every list is plain (not
// negated, in the background or a coprocess), the command defines no
// function and has no here-document, the twin analysis is complete, and
// every command in it is a plain POSIX process with a static argv.
func ShortCircuitListReduction(input Input, facts Facts) (view Facts, ok bool) {
	return sequenceReduction(input, facts, false)
}

// CompoundCommandReduction returns a complete view of a partial POSIX action
// whose simple commands sit in compound commands, read as if each of them
// runs alone: a subshell, a { } group, the bodies and conditions of if,
// while, until, for and case, a negated or background statement, and && or ||
// lists. A block stops the whole tool call before any of it runs, so a rule
// that blocks `rm -rf /` also blocks `(rm -rf /)` and
// `if true; then rm -rf /; fi`. facts must be Analyze(input).
//
// The view is the analysis of a twin of the command in which each simple
// command is a statement of its own. A subshell or group no longer scopes the
// directory or variables of its commands there, and a loop runs its body
// once, so callers may count only a match on the view, for an expression that
// more commands cannot turn off.
//
// The view is unavailable when a compound command carries a redirect, a for
// or case word runs a command, a statement is a coprocess, the command
// defines a function or has a here-document, the twin analysis is not
// complete, or a command in it is not a plain POSIX process with a static
// argv.
func CompoundCommandReduction(input Input, facts Facts) (view Facts, ok bool) {
	return sequenceReduction(input, facts, true)
}

func sequenceReduction(input Input, facts Facts, compound bool) (view Facts, ok bool) {
	defer func() {
		if recover() != nil {
			view, ok = Facts{}, false
		}
	}()
	if facts.Parse.Status != StatusPartial || len(facts.Commands) == 0 ||
		!containsIssue(facts.Parse.Issues, IssueUnsupportedConstruct) {
		return Facts{}, false
	}
	original, capture := analyzeWithRedirectTargets(input, "")
	if original.Parse.Status != StatusPartial {
		return Facts{}, false
	}
	twinSource, ok := shortCircuitListSequence(capture.source, compound)
	if !ok {
		return Facts{}, false
	}
	twin, _ := analyzeWithRedirectTargets(input, twinSource)
	if !twin.Authoritative() && containsIssue(twin.Parse.Issues, IssueDynamicWord) {
		// A list member may be a plain pipeline. Resolve its home operands
		// after flattening the list, so the existing complete-facts check
		// still controls whether this projection can prove a rule.
		home, _ := normalizeActiveHome(input.ActiveHome)
		if trustedPOSIXHomeLiteral.MatchString(home) {
			if resolved, ok := homeResolvedSource(twinSource, home); ok {
				twin, _ = analyzeWithRedirectTargets(input, resolved)
			}
		}
	}
	if !twin.Authoritative() || len(twin.Parse.Issues) != 0 ||
		twin.Parse.Dialect != facts.Parse.Dialect || len(twin.Commands) == 0 {
		return Facts{}, false
	}
	for _, command := range twin.Commands {
		if !plainPOSIXProcess(command) {
			return Facts{}, false
		}
	}
	return twin, true
}

// shortCircuitListSequence returns source with each top-level && or || list
// replaced by its commands, one statement per line; with compound, also each
// subshell, group, if, while, until, for and case, and each negated or
// background statement. It declines a source with nothing to replace, one
// with a negated, background (unless compound) or coprocess statement in a
// list, one where a dropped word could run a command (a for or case word with
// a command substitution) or a redirect of a replaced compound command would
// be lost, and one where a statement could change what another runs (a
// function definition) or where cutting the text could lose input (a
// here-document).
func shortCircuitListSequence(source string, compound bool) (string, bool) {
	if source == "" {
		return "", false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(strings.NewReader(source), "")
	if err != nil {
		return "", false
	}
	declined := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.FuncDecl:
			declined = true
		case *syntax.Redirect:
			declined = declined || typed.Op == syntax.Hdoc || typed.Op == syntax.DashHdoc
		}
		return !declined
	})
	if declined {
		return "", false
	}
	kept := make([]string, 0, len(file.Stmts))
	reduced := false
	keep := func(node syntax.Node) bool {
		start, end := int(node.Pos().Offset()), int(node.End().Offset())
		if start < 0 || end <= start || end > len(source) {
			return false
		}
		kept = append(kept, source[start:end])
		return true
	}
	var flatten func(stmt *syntax.Stmt) bool
	flattenAll := func(stmts []*syntax.Stmt) bool {
		for _, stmt := range stmts {
			if !flatten(stmt) {
				return false
			}
		}
		return true
	}
	// flattenCompound replaces a compound command by its statements. It
	// reports whether command is one it replaces, and whether that worked.
	flattenCompound := func(command syntax.Command) (replaced, ok bool) {
		switch typed := command.(type) {
		case *syntax.BinaryCmd:
			if typed.Op != syntax.AndStmt && typed.Op != syntax.OrStmt {
				return false, false
			}
			return true, flatten(typed.X) && flatten(typed.Y)
		}
		if !compound {
			return false, false
		}
		switch typed := command.(type) {
		case *syntax.Subshell:
			return true, flattenAll(typed.Stmts)
		case *syntax.Block:
			return true, flattenAll(typed.Stmts)
		case *syntax.IfClause:
			for clause := typed; clause != nil; clause = clause.Else {
				if !flattenAll(clause.Cond) || !flattenAll(clause.Then) {
					return true, false
				}
			}
			return true, true
		case *syntax.WhileClause:
			return true, flattenAll(typed.Cond) && flattenAll(typed.Do)
		case *syntax.ForClause:
			iteration, isWords := typed.Loop.(*syntax.WordIter)
			if !isWords || !inertPOSIXWords(iteration.Items...) {
				return true, false
			}
			return true, flattenAll(typed.Do)
		case *syntax.CaseClause:
			if !inertPOSIXWords(typed.Word) {
				return true, false
			}
			for _, item := range typed.Items {
				if !inertPOSIXWords(item.Patterns...) || !flattenAll(item.Stmts) {
					return true, false
				}
			}
			return true, true
		}
		return false, false
	}
	flatten = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Coprocess || stmt.Disown {
			return false
		}
		if stmt.Negated || stmt.Background {
			if !compound || len(stmt.Redirs) != 0 {
				return false
			}
			reduced = true
			if replaced, ok := flattenCompound(stmt.Cmd); replaced {
				return ok
			}
			return stmt.Cmd != nil && keep(stmt.Cmd)
		}
		if len(stmt.Redirs) == 0 {
			if replaced, ok := flattenCompound(stmt.Cmd); replaced {
				reduced = true
				return ok
			}
		}
		return keep(stmt)
	}
	if !flattenAll(file.Stmts) || !reduced {
		return "", false
	}
	return strings.Join(kept, "\n"), true
}

// inertPOSIXWords reports whether words run no command when the shell
// expands them.
func inertPOSIXWords(words ...*syntax.Word) bool {
	inert := true
	for _, word := range words {
		syntax.Walk(word, func(node syntax.Node) bool {
			switch node.(type) {
			case *syntax.CmdSubst, *syntax.ProcSubst:
				inert = false
			}
			return inert
		})
	}
	return inert
}
