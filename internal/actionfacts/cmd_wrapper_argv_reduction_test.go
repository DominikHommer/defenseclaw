// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestOpaqueCMDWrapperArgvReductionKeepsOnlyExactOuterArguments(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"unquoted body", `cmd.exe /c echo dccert-block-marker > marker.txt`, true},
		{"quoted body is already complete", `cmd.exe /c "echo dccert-block-marker > marker.txt"`, false},
		{"dynamic argument", `cmd.exe /c echo $env:MARKER > marker.txt`, false},
		{"separate command", `cmd.exe /c echo dccert-block-marker > marker.txt; Write-Output done`, false},
		{"no cmd wrapper", `Set-Content marker.txt dccert-block-marker`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "powershell", Command: tc.command, DialectHint: DialectPowerShell})
			view, ok := OpaqueCMDWrapperArgvReduction(facts)
			if ok != tc.want {
				t.Fatalf("reduced=%t, want %t; parse=%+v commands=%+v", ok, tc.want, facts.Parse, facts.Commands)
			}
			if !ok {
				return
			}
			if facts.Authoritative() || !view.Authoritative() || !view.EnforcementEligible() ||
				len(view.Commands) != 1 || !view.Commands[0].ArgvComplete ||
				len(view.Commands[0].Operations) != 0 || len(view.Commands[0].Redirects) != 0 ||
				len(view.Paths) != 0 || len(view.Network) != 0 ||
				view.Commands[0].Argv[2] != "echo" || view.Commands[0].Argv[3] != "dccert-block-marker" {
				t.Fatalf("view kept more than exact outer argv: %+v", view)
			}
		})
	}
}
