// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// OpaqueCMDWrapperArgvReduction keeps the exact outer argv of a PowerShell
// call to cmd.exe /c whose unquoted body cannot be parsed as a complete child
// command. CMD AutoRun may execute before the body, so the full action stays
// partial. A caller may use only a positive, monotone match on this argv;
// absence of a match proves nothing about the child or AutoRun.
func OpaqueCMDWrapperArgvReduction(facts Facts) (Facts, bool) {
	if facts.Parse.Status != StatusPartial || facts.Parse.Dialect != DialectPowerShell ||
		len(facts.Parse.Issues) != 1 || facts.Parse.Issues[0] != IssueUnsupportedConstruct ||
		len(facts.Commands) != 1 {
		return Facts{}, false
	}
	command := facts.Commands[0]
	if command.ParentCommandID != 0 || command.Program != "cmd" ||
		(command.Executable != "cmd" && command.Executable != "cmd.exe") ||
		command.Dialect != DialectPowerShell || command.Background || command.ControlFlowUncertain ||
		!command.ArgvComplete || len(command.Argv) < 4 || len(command.Arguments) != len(command.Argv) ||
		!strings.EqualFold(command.Argv[1], "/c") {
		return Facts{}, false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.StaticGlob != "" {
			return Facts{}, false
		}
	}
	// Only the outer process and its argv are certain. Derived operations,
	// redirects and paths, and everything cmd.exe or AutoRun may run, are omitted.
	command.Operations = nil
	command.Redirects = nil
	command.Wrappers = nil
	return Facts{
		Tool: facts.Tool, CWD: facts.CWD, ActiveHome: facts.ActiveHome,
		Parse:    ParseResult{Status: StatusComplete, Dialect: DialectPowerShell},
		Commands: []CommandFact{command},
	}, true
}
