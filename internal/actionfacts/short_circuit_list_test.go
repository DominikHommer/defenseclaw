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
	"testing"
)

// GAP-0616: each statement of a compound command is analysed as if it ran
// alone, with the redirects of the compound commands around it.
func TestStatementsAlone(t *testing.T) {
	tests := []struct {
		command string
		// want is the argv of each view's commands, one statement per entry.
		want []string
	}{
		{"(echo m); echo $USER", []string{"echo m", "echo"}},
		{"if true; then echo m; fi; echo $HOME", []string{"true", "echo m", "echo"}},
		{"rm -rf /; echo $HOME", []string{"rm -rf /", "echo"}},
		{"(rm -rf /) 2>&1", []string{"rm -rf /"}},
		{"rm -rf / 2>&1", []string{"rm -rf /"}},
		{"(cd /tmp && rm -rf /) > /tmp/log 2>&1", []string{"cd /tmp", "rm -rf /"}},
		{"(exit 0); echo m", []string{"echo m"}},
		// A relative path after a command that may change the directory.
		{"cd /tmp; rm -rf x; echo $HOME", []string{"cd /tmp", "echo"}},
		// What the other statements run may change.
		{"cd $DIR; echo m", nil},
		{"export PATH=$DIR; echo m $USER", nil},
		{"$CMD; echo m", nil},
		{"f() { echo m; }; f $X", nil},
		{"for i in $(ls); do echo m; done", nil},
		// One statement with nothing to leave out is the action.
		{"echo m $USER", nil},
	}
	for _, test := range tests {
		input := Input{Tool: "shell", Command: test.command, CWD: "/home/alice/project", ActiveHome: "/home/alice", DialectHint: DialectPOSIX}
		var got []string
		for _, statement := range StatementsAlone(input, Analyze(input)) {
			if !statement.View.Authoritative() {
				t.Errorf("%q: view is not complete: %+v", test.command, statement.View.Parse)
			}
			var argv []string
			for _, command := range statement.View.Commands {
				argv = append(argv, strings.Join(command.Argv, " "))
			}
			got = append(got, strings.Join(argv, " | "))
		}
		if !slices.Equal(got, test.want) {
			t.Errorf("%q: statements alone = %q, want %q", test.command, got, test.want)
		}
	}
}

func TestCompoundCommandReductionMovesRedirectsAndSubshellExit(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"{ echo m; } > /dev/null", "echo m > /dev/null"},
		{"while read l; do echo m; done < /etc/hosts", "read l < /etc/hosts\necho m < /etc/hosts"},
		{"{ (echo m) 2>/dev/null; } > /tmp/out", "echo m 2>/dev/null > /tmp/out"},
		{"! echo m > /tmp/out", "echo m > /tmp/out"},
		{"(exit 0); echo m", "echo m"},
		{"(if true; then exit 1; fi); echo m", "true\necho m"},
		{"{ exit 0; }; echo m", "exit 0\necho m"},
	}
	for _, test := range tests {
		got, ok := shortCircuitListSequence(test.command, true)
		if !ok || got != test.want {
			t.Errorf("%q: sequence = %q, %t, want %q", test.command, got, ok, test.want)
		}
	}
	for _, command := range []string{"(echo m) 2>/dev/null", "(exit 0); echo m"} {
		input := Input{Tool: "shell", Command: command, CWD: "/tmp", DialectHint: DialectPOSIX}
		if _, ok := CompoundCommandReduction(input, Analyze(input)); !ok {
			t.Errorf("%q: no compound command view", command)
		}
	}
}
