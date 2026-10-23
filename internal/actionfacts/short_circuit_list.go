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
	"slices"
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
// command is a statement of its own, with the redirects of the compound
// commands around it, and without an exit that only ends a subshell. A
// subshell or group no longer scopes the directory or variables of its
// commands there, and a loop runs its body once, so callers may count only a
// match on the view, for an expression that more commands cannot turn off.
//
// The view is unavailable when a for or case word runs a command, a
// statement is a coprocess, the command defines a function or has a
// here-document, the twin analysis is not complete, or a command in it is not
// a plain POSIX process with a static argv.
func CompoundCommandReduction(input Input, facts Facts) (view Facts, ok bool) {
	return sequenceReduction(input, facts, true)
}

// maxStatementsAlone bounds the statements StatementsAlone analyses.
const maxStatementsAlone = 128

// StatementAlone is one statement of an action analysed as if it were the
// whole tool call. View is a complete view of it: its analysis, or for a
// statement that is partial alone, its StaticCommandSubsetReduction view
// (Subset set, and PartialArgv as that reduction reports it).
type StatementAlone struct {
	View Facts
	// Source is the original statement text when View is its complete
	// analysis. It is empty for a reduction that dropped a duplication or
	// dynamic words, since a legacy regex must see the exact statement.
	Source      string
	Subset      bool
	PartialArgv bool
}

// StatementsAlone returns each statement of a partial POSIX action analysed
// as if it ran alone: the statements of CompoundCommandReduction's twin (the
// commands of && and || lists, subshells, groups, if, loop and case bodies,
// and negated and background statements, with the redirects of the compound
// commands around them), each with the context of input. A statement that is
// partial alone because of a descriptor duplication (2>&1) is analysed
// without it, as is an action of one such statement. facts must be
// Analyze(input).
//
// A block stops the whole tool call before any of it runs, so a rule that
// blocks a statement alone also blocks the action (GAP-0616): `(rm -rf /);
// echo $HOME` as `rm -rf /`. A statement alone lacks the other statements,
// how they change the shell, and the duplications left out, so a caller may
// count only a match on a view, for an expression that more commands,
// redirects and data flows cannot turn off. A statement with a relative path
// is left out when a command of the action may change the directory
// (ChangesShellDirectory), and one that is partial alone is left out unless
// it has a StaticCommandSubsetReduction view. Nothing is returned when the
// action defines a function, has a here-document, a coprocess, or a for or
// case word that runs a command, or when a command whose program expands or
// a shell builtin with a runtime-expanded word may change what the others
// run. At most maxStatementsAlone statements are analysed.
func StatementsAlone(input Input, facts Facts) (statements []StatementAlone) {
	defer func() {
		if recover() != nil {
			statements = nil
		}
	}()
	if facts.Parse.Status != StatusPartial || facts.Parse.Dialect != DialectPOSIX ||
		len(facts.Commands) == 0 {
		return nil
	}
	_, capture := analyzeWithRedirectTargets(input, "")
	// A bash function, or a zsh anonymous one (`function\n{ ...; }`), is
	// not a POSIX one.
	if definesFunction(capture.source) {
		return nil
	}
	texts, reduced, ok := sequenceStatements(capture.source, true)
	if !ok {
		return nil
	}
	// One statement alone is the action, which only its duplications may
	// leave partial.
	single := !reduced && len(texts) == 1
	// As for StaticCommandSubsetReduction, a shell builtin with a
	// runtime-expanded word (cd $DIR, export PATH=$DIR, eval "$X") or a
	// command whose program expands may change what the others run. A bare
	// assignment has no program; only one that changes shell resolution or
	// startup state needs to stop the pass.
	bareAssignments := 0
	for _, statement := range texts {
		assignment, safe := bareAssignmentStatement(statement)
		if assignment {
			if !safe {
				return nil
			}
			bareAssignments++
		}
	}
	blankPrograms := 0
	if slices.ContainsFunc(facts.Commands, func(command CommandFact) bool {
		if strings.TrimSpace(command.Program) == "" {
			blankPrograms++
			return false
		}
		return shellStateBuiltins[strings.ToLower(command.Program)] &&
			slices.ContainsFunc(command.Arguments, func(argument ArgumentFact) bool {
				return argument.Expands || argument.StaticGlob != ""
			})
	}) || blankPrograms != bareAssignments {
		return nil
	}
	directoryMayChange := slices.ContainsFunc(facts.Commands, ChangesShellDirectory)
	home, _ := normalizeActiveHome(input.ActiveHome)
	alone := input
	alone.Args, alone.Argv = nil, nil
	for _, text := range texts[:min(len(texts), maxStatementsAlone)] {
		alone.Command = text
		view := Analyze(alone)
		legacySource := ""
		if view.Authoritative() {
			legacySource = text
		}
		if !view.Authoritative() || single {
			stripped, ok := withoutDescriptorDuplications(text)
			if !ok && single {
				return nil
			}
			if ok {
				alone.Command = stripped
				view = Analyze(alone)
			}
		}
		if view.Parse.Dialect != DialectPOSIX || (directoryMayChange &&
			slices.ContainsFunc(view.Paths, func(path PathFact) bool {
				return !path.Absolute && !homeAnchoredPath(path, home)
			})) {
			continue
		}
		if assignment, _ := bareAssignmentStatement(text); assignment {
			continue
		}
		if view.Authoritative() {
			statements = append(statements, StatementAlone{View: view, Source: legacySource})
			continue
		}
		if subset, partialArgv, ok := StaticCommandSubsetReduction(alone, view); ok {
			statements = append(statements, StatementAlone{View: subset, Subset: true, PartialArgv: partialArgv})
		}
	}
	return statements
}

// homeAnchoredPath is independent of the shell's current directory even
// though its original tilde spelling is recorded as a non-absolute path.
func homeAnchoredPath(path PathFact, home string) bool {
	if home == "" || path.Flavor != PathFlavorPOSIX ||
		(path.Value != "~" && !strings.HasPrefix(path.Value, "~/")) {
		return false
	}
	return path.Resolved == home+strings.TrimPrefix(path.Value, "~")
}

// bareAssignmentStatement reports whether a statement only assigns ordinary
// variables, without running a command substitution or changing how later
// commands or paths resolve.
func bareAssignmentStatement(source string) (assignment, safe bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(strings.NewReader(source), "")
	if err != nil || len(file.Stmts) != 1 {
		return false, false
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) == 0 {
		return false, false
	}
	if len(stmt.Redirs) != 0 || stmt.Background || stmt.Negated || stmt.Coprocess {
		return true, false
	}
	for _, item := range call.Assigns {
		if item == nil || item.Name == nil || item.Index != nil || item.Array != nil ||
			(item.Value != nil && !inertPOSIXWords(item.Value)) ||
			shellResolutionAssignment(item.Name.Value) {
			return true, false
		}
	}
	return true, true
}

func shellResolutionAssignment(name string) bool {
	if strings.HasPrefix(name, "LD_") {
		return true
	}
	switch name {
	case "PATH", "IFS", "HOME", "CDPATH", "ENV", "BASH_ENV", "SHELLOPTS",
		"BASHOPTS", "GLOBIGNORE", "FPATH", "ZDOTDIR", "PWD", "OLDPWD":
		return true
	}
	return false
}

// withoutDescriptorDuplications returns statement without its descriptor
// duplications (2>&1, <&3, >&-), and reports whether it had any.
func withoutDescriptorDuplications(statement string) (string, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(strings.NewReader(statement), "")
	if err != nil {
		return "", false
	}
	var cuts [][2]int
	syntax.Walk(file, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok &&
			(redirect.Op == syntax.DplIn || redirect.Op == syntax.DplOut) {
			cuts = append(cuts, [2]int{int(redirect.Pos().Offset()), int(redirect.End().Offset())})
		}
		return true
	})
	if len(cuts) == 0 {
		return "", false
	}
	// Walk visits redirects in source order; cut from the last.
	for index := len(cuts) - 1; index >= 0; index-- {
		start, end := cuts[index][0], cuts[index][1]
		if start < 0 || end <= start || end > len(statement) {
			return "", false
		}
		statement = statement[:start] + statement[end:]
	}
	return statement, true
}

// shellDirectoryCommands are the POSIX commands that change the directory of
// the shell that runs them or run text that may.
var shellDirectoryCommands = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "source": true, ".": true,
	"eval": true, "exec": true, "builtin": true, "command": true,
	"alias": true, "trap": true,
}

// ChangesShellDirectory reports whether command may change the directory
// later commands of its action run in: a POSIX command that changes it or
// runs text that may, or one whose program is not static. A PowerShell or
// cmd.exe script shares its caller's location, so there any command may.
func ChangesShellDirectory(command CommandFact) bool {
	if command.Dialect != DialectPOSIX {
		return true
	}
	program := strings.ToLower(strings.TrimSpace(command.Program))
	return program == "" || shellDirectoryCommands[program]
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
// background statement (sequenceStatements). It declines a source with
// nothing to replace.
func shortCircuitListSequence(source string, compound bool) (string, bool) {
	statements, reduced, ok := sequenceStatements(source, compound)
	if !ok || !reduced {
		return "", false
	}
	return strings.Join(statements, "\n"), true
}

// sequenceStatements returns the statements of source with each top-level &&
// or || list replaced by its commands, and reports whether it replaced
// anything. With compound, it also replaces each subshell, group, if, while,
// until, for and case by the statements in it, and a negated or background
// statement by its command. A redirect of a replaced compound command is
// moved onto each statement in it, which then writes or reads what the
// compound command did, and an exit in a subshell, which ends only that
// subshell, is left out. It declines a source with a negated, background
// (unless compound) or coprocess statement in a list, one where a dropped
// word could run a command (a for or case word with a command substitution),
// and one where a statement could change what another runs (a function
// definition) or where cutting the text could lose input (a here-document).
func sequenceStatements(source string, compound bool) (statements []string, reduced, ok bool) {
	if source == "" {
		return nil, false, false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(strings.NewReader(source), "")
	if err != nil {
		return nil, false, false
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
		return nil, false, false
	}
	statements = make([]string, 0, len(file.Stmts))
	text := func(from, to syntax.Pos) (string, bool) {
		start, end := int(from.Offset()), int(to.Offset())
		if start < 0 || end <= start || end > len(source) {
			return "", false
		}
		return source[start:end], true
	}
	// redirects are those of the compound commands being replaced, outermost
	// first, as text to append to each statement.
	var redirects []string
	// keep adds the text of node, or of a command and its redirects.
	keep := func(node syntax.Node, redirs ...*syntax.Redirect) bool {
		from, to := node.Pos(), node.End()
		for _, redirect := range redirs {
			if redirect.Pos().Offset() < from.Offset() {
				from = redirect.Pos()
			}
			if redirect.End().Offset() > to.Offset() {
				to = redirect.End()
			}
		}
		statement, ok := text(from, to)
		if !ok {
			return false
		}
		for index := len(redirects) - 1; index >= 0; index-- {
			statement += " " + redirects[index]
		}
		statements = append(statements, statement)
		return true
	}
	subshells := 0
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
			if typed.Op != syntax.AndStmt && typed.Op != syntax.OrStmt &&
				(!compound || (typed.Op != syntax.Pipe && typed.Op != syntax.PipeAll) ||
					!pipelineHasCompoundCommand(typed)) {
				return false, false
			}
			return true, flatten(typed.X) && flatten(typed.Y)
		}
		if !compound {
			return false, false
		}
		switch typed := command.(type) {
		case *syntax.Subshell:
			subshells++
			defer func() { subshells-- }()
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
	// flattenRedirected replaces the compound command of stmt with its
	// redirects moved onto the statements in it.
	flattenRedirected := func(stmt *syntax.Stmt) (replaced, ok bool) {
		if len(stmt.Redirs) == 0 {
			return flattenCompound(stmt.Cmd)
		}
		if !compound {
			return false, false
		}
		moved, ok := text(stmt.Redirs[0].Pos(), stmt.Redirs[len(stmt.Redirs)-1].End())
		if !ok {
			return false, false
		}
		saved := redirects
		redirects = append(redirects[:len(redirects):len(redirects)], moved)
		defer func() { redirects = saved }()
		return flattenCompound(stmt.Cmd)
	}
	flatten = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Coprocess || stmt.Disown {
			return false
		}
		if compound && subshells > 0 && !stmt.Negated && !stmt.Background &&
			len(stmt.Redirs) == 0 && subshellExit(stmt.Cmd) {
			reduced = true
			return true
		}
		if stmt.Negated || stmt.Background {
			if !compound {
				return false
			}
			reduced = true
			if replaced, ok := flattenRedirected(stmt); replaced {
				return ok
			}
			return stmt.Cmd != nil && keep(stmt.Cmd, stmt.Redirs...)
		}
		if replaced, ok := flattenRedirected(stmt); replaced {
			reduced = true
			return ok
		}
		if stmt.Cmd == nil {
			return len(stmt.Redirs) != 0 && keep(stmt.Redirs[0], stmt.Redirs...)
		}
		// Not stmt itself, whose text may end in a ; that a moved redirect
		// cannot follow.
		return keep(stmt.Cmd, stmt.Redirs...)
	}
	if !flattenAll(file.Stmts) {
		return nil, false, false
	}
	return statements, reduced, true
}

// pipelineHasCompoundCommand keeps an ordinary pipeline intact. Its data
// flow can be part of an exact rule's proof. A compound element needs its
// inner statements exposed to the match-only pass.
func pipelineHasCompoundCommand(binary *syntax.BinaryCmd) bool {
	var contains func(*syntax.Stmt) bool
	contains = func(stmt *syntax.Stmt) bool {
		if stmt == nil {
			return false
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.Subshell, *syntax.Block, *syntax.IfClause,
			*syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
			return true
		case *syntax.BinaryCmd:
			if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
				return contains(cmd.X) || contains(cmd.Y)
			}
		}
		return false
	}
	return contains(binary.X) || contains(binary.Y)
}

// subshellExit reports whether command is a plain exit, which in a subshell
// ends only the subshell.
func subshellExit(command syntax.Command) bool {
	call, ok := command.(*syntax.CallExpr)
	return ok && len(call.Assigns) == 0 && len(call.Args) != 0 &&
		call.Args[0].Lit() == "exit" && inertPOSIXWords(call.Args...)
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
