// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"unicode"
)

// OpaqueCMDWrapperArgvReduction keeps the exact outer argv of a PowerShell
// call to cmd.exe /c whose unquoted body cannot be parsed as a complete child
// command. CMD AutoRun may execute before the body, so the full action stays
// partial. A caller may use only a positive, monotone match on this argv;
// absence of a match proves nothing about the child or AutoRun.
func OpaqueCMDWrapperArgvReduction(input Input, facts Facts) (Facts, bool) {
	// PowerShell permits a call operator before a bare executable, but the
	// general parser treats that form as an opaque expression. Reparse only
	// the static command after a leading call operator. Both parses must
	// describe one command, with no other uncertainty in the original.
	commandText := input.Command
	if commandText == "" && len(input.Args) > 0 {
		extracted := extractArgsForTool(input.Args, input.Tool)
		if extracted.status == StatusComplete && len(extracted.argv) == 0 {
			commandText = extracted.command
		}
	}
	callOperator := callOperatorCMD(commandText, facts) && len(input.Argv) == 0
	if callOperator {
		trimmed := strings.TrimLeftFunc(commandText, unicode.IsSpace)
		input.Command = strings.TrimLeftFunc(trimmed[1:], unicode.IsSpace)
		// The tool may have supplied its working directory inside Args.
		// Keep that verified context when dropping the original arguments.
		input.CWD = facts.CWD
		input.ActiveHome = facts.ActiveHome
		input.Args = nil
		facts = Analyze(input)
	}
	if facts.Parse.Status != StatusPartial || facts.Parse.Dialect != DialectPowerShell ||
		len(facts.Parse.Issues) != 1 || facts.Parse.Issues[0] != IssueUnsupportedConstruct ||
		len(facts.Commands) == 0 || callOperator && len(facts.Commands) != 1 {
		return Facts{}, false
	}
	// A PowerShell list (cmd.exe /c ... && type out.txt) keeps every command
	// of the list. Each must have a complete static argv, and each cmd.exe in
	// it must be a wrapper this reduction accepts.
	commands := make([]CommandFact, 0, len(facts.Commands))
	wrapped := false
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.Dialect != DialectPowerShell || command.Background ||
			command.ControlFlowUncertain || !command.ArgvComplete || len(command.Argv) == 0 ||
			len(command.Arguments) != len(command.Argv) {
			return Facts{}, false
		}
		for _, argument := range command.Arguments {
			if argument.Expands || argument.StaticGlob != "" {
				return Facts{}, false
			}
		}
		if command.Program != "cmd" {
			commands = append(commands, command)
			continue
		}
		if !opaqueCMDWrapper(command, len(facts.Commands) == 1) {
			return Facts{}, false
		}
		// Only the outer process and its argv are certain. Derived
		// operations, redirects and paths, and everything cmd.exe or AutoRun
		// may run, are omitted.
		command.Operations = nil
		command.Redirects = nil
		command.Wrappers = nil
		commands = append(commands, command)
		wrapped = true
	}
	if !wrapped {
		return Facts{}, false
	}
	return Facts{
		Tool: facts.Tool, CWD: facts.CWD, ActiveHome: facts.ActiveHome,
		Parse:    ParseResult{Status: StatusComplete, Dialect: DialectPowerShell},
		Commands: commands,
	}, true
}

// opaqueCMDWrapper reports a cmd.exe call whose argv is static options, then
// /c or /r (its synonym), then an unquoted body: cmd.exe /c echo x > out.txt,
// cmd.exe /d/c ..., cmd.exe /r .... alone is set for the only command of the
// action: a sole quoted body there already has a complete argument boundary
// and the ordinary wrapper analysis handles it.
func opaqueCMDWrapper(command CommandFact, alone bool) bool {
	if command.Executable != "cmd" && command.Executable != "cmd.exe" || len(command.Argv) < 3 {
		return false
	}
	commandSwitch := 1
	for commandSwitch < len(command.Argv) {
		options, run := cmdSwitches(command.Argv[commandSwitch])
		if !options {
			return false
		}
		commandSwitch++
		if run {
			break
		}
		if commandSwitch == len(command.Argv) {
			return false
		}
	}
	if commandSwitch >= len(command.Argv) {
		return false
	}
	return !alone || commandSwitch+1 != len(command.Argv) || command.Arguments[commandSwitch].Quote == QuoteNone
}

// cmdSwitches reads one cmd.exe argument of switches, which cmd.exe also
// takes joined (/d/c): ok when every switch is a static option or a final
// /c or /r, and run when the argument ends with /c or /r.
func cmdSwitches(value string) (ok, run bool) {
	if !strings.HasPrefix(value, "/") || len(value) < 2 {
		return false, false
	}
	parts := strings.Split(value[1:], "/")
	for index, part := range parts {
		switch strings.ToLower(part) {
		case "c", "r":
			if index != len(parts)-1 {
				return false, false
			}
			return true, true
		}
		if !staticCMDOption("/" + part) {
			return false, false
		}
	}
	return true, false
}

func staticCMDOption(value string) bool {
	switch strings.ToLower(value) {
	case "/d", "/q", "/s", "/a", "/u":
		return true
	}
	value = strings.ToLower(value)
	for _, prefix := range []string{"/e:", "/v:", "/f:"} {
		if strings.HasPrefix(value, prefix) {
			return value[len(prefix):] == "on" || value[len(prefix):] == "off"
		}
	}
	if !strings.HasPrefix(value, "/t:") || len(value) < 4 || len(value) > 5 {
		return false
	}
	for _, digit := range value[3:] {
		if digit < '0' || digit > '9' && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

func callOperatorCMD(command string, facts Facts) bool {
	if facts.Parse.Status != StatusPartial || facts.Parse.Dialect != DialectPowerShell ||
		len(facts.Parse.Issues) != 2 || facts.Parse.Issues[0] != IssueUnsupportedConstruct ||
		facts.Parse.Issues[1] != IssueDynamicWord || len(facts.Commands) != 1 {
		return false
	}
	opaque := facts.Commands[0]
	if opaque.ParentCommandID != 0 || opaque.Background || opaque.ControlFlowUncertain ||
		opaque.Program != "" || opaque.Executable != "" || opaque.Effect != EffectUncertain ||
		opaque.ArgvComplete || len(opaque.Argv) != 0 || len(opaque.Arguments) != 1 ||
		opaque.Arguments[0].Value != "&" || !opaque.Arguments[0].Expands {
		return false
	}
	trimmed := strings.TrimLeftFunc(command, unicode.IsSpace)
	// "& cmd.exe" and "&cmd.exe" are the same call; "&&" is not a call.
	if !strings.HasPrefix(trimmed, "&") || len(trimmed) < 2 || trimmed[1] == '&' {
		return false
	}
	return true
}
