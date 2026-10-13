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

//go:build !windows

package sandboxcli

import (
	"slices"
	"strings"
	"testing"
)

// #1074: the record of a run kept an option whose value held a space
// without the value (a later connect started the harness with a valueless
// option, which Claude Code refuses), and kept a one-word prompt after a
// switch as the switch's value (a later connect replayed it). An option
// the harness takes a value with keeps its value whatever it holds; one it
// takes none with keeps no word.
func TestLaunchOptionsUseTheHarnessesOptionArity(t *testing.T) {
	for _, c := range []struct {
		harness string
		args    []string
		want    []string
	}{
		{"claudecode", []string{"--append-system-prompt", "be brief"}, []string{"--append-system-prompt", "be brief"}},
		{"claudecode", []string{"--append-system-prompt", "be brief", "--model", "sonnet", "fix it"}, []string{"--append-system-prompt", "be brief", "--model", "sonnet"}},
		{"claudecode", []string{"--verbose", "fixit"}, []string{"--verbose"}},
		{"claudecode", []string{"--verbose", "--model", "sonnet", "fixit"}, []string{"--verbose", "--model", "sonnet"}},
		{"claudecode", []string{"--permission-mode", "plan", "-c"}, []string{"--permission-mode", "plan", "-c"}},
		// A value option at the end of the options, then `--`, keeps no word.
		{"claudecode", []string{"--model", "--", "x"}, []string{"--model"}},
		{"codex", []string{"-m", "glm 5.3", "-c", "model_reasoning_effort=high"}, []string{"-m", "glm 5.3", "-c", "model_reasoning_effort=high"}},
		{"codex", []string{"--full-auto", "fixit"}, []string{"--full-auto"}},
		{"opencode", []string{"--agent", "plan mode", "-c", "fixit"}, []string{"--agent", "plan mode", "-c"}},
		{"copilot", []string{"--model", "claude sonnet", "--allow-all-paths", "fixit"}, []string{"--model", "claude sonnet", "--allow-all-paths"}},
		{"hermes", []string{"chat", "--provider", "defenseclaw", "-m", "gpt 5 mini", "--yolo", "fixit"},
			[]string{"chat", "--provider", "defenseclaw", "-m", "gpt 5 mini", "--yolo"}},
		// A harness without a table reads values from their shape, as before.
		{"amp", []string{"--some-option", "value", "fix it"}, []string{"--some-option", "value"}},
	} {
		if got := launchOptions(harnessSpec(t, c.harness), c.args); !slices.Equal(got, c.want) {
			t.Errorf("%s: launchOptions(%q) = %q, want %q", c.harness, c.args, got, c.want)
		}
	}
}

// #1074 end to end: `connect` after a run whose option value holds a space
// starts the harness with the option and its value, and without the
// one-word prompt that followed a switch; the run warns of nothing.
func TestConnectKeepsASpacedRunOptionValue(t *testing.T) {
	ta := newTestApp(t, "")
	noChanges(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Name: "sp1", Args: []string{"--append-system-prompt", "be brief", "--verbose", "fixit"}}))
	lacks(t, ta.output(), "followed by a word with a space", "without the last word")
	ta.out.Reset()
	ta.term.runs = nil
	ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "sp1"}))
	if len(ta.term.runs) != 1 {
		t.Fatalf("terminal runs = %q", ta.term.runs)
	}
	argv := ta.term.runs[0]
	at := slices.Index(argv, "--append-system-prompt")
	if at < 0 || at+1 >= len(argv) || argv[at+1] != "be brief" {
		t.Fatalf("connect argv = %q, want --append-system-prompt with its value", argv)
	}
	if !slices.Contains(argv, "--verbose") || slices.Contains(argv, "fixit") {
		t.Fatalf("connect argv = %q, want --verbose without the run's prompt", argv)
	}
	if strings.Contains(strings.Join(argv, " "), "--append-system-prompt --verbose") {
		t.Fatalf("connect argv = %q: the option lost its value", argv)
	}
}
