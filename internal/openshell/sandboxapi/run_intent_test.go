// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRunIntentOwnsBoundedClientData(t *testing.T) {
	input := &RunIntent{Mode: "headless", Prompt: "fix the tests\nwithout network", Args: []string{"--model", "sonnet"}}
	owned, err := OwnRunIntent(input)
	if err != nil || owned == nil || owned == input || owned.Mode != input.Mode || owned.Prompt != input.Prompt {
		t.Fatalf("owned run intent: %#v, %v", owned, err)
	}
	input.Args[0] = "--changed-after-admission"
	if owned.Args[0] != "--model" {
		t.Fatal("run intent retained caller-backed argument storage")
	}
	if empty, err := OwnRunIntent(nil); empty != nil || err != nil {
		t.Fatalf("optional fixed preparation intent: %#v, %v", empty, err)
	}
}

func TestRunIntentRejectsMalformedOrUnboundedValues(t *testing.T) {
	valid := RunIntent{Mode: "headless", Prompt: "literal prompt"}
	cases := map[string]RunIntent{
		"interactive":     {Mode: "interactive", Prompt: valid.Prompt},
		"empty prompt":    {Mode: valid.Mode},
		"blank prompt":    {Mode: valid.Mode, Prompt: " \n"},
		"nul prompt":      {Mode: valid.Mode, Prompt: "a\x00b"},
		"oversize prompt": {Mode: valid.Mode, Prompt: strings.Repeat("p", runIntentPromptBytes+1)},
		"invalid utf8":    {Mode: valid.Mode, Prompt: string([]byte{0xff})},
		"empty argument":  {Mode: valid.Mode, Prompt: valid.Prompt, Args: []string{""}},
		"nul argument":    {Mode: valid.Mode, Prompt: valid.Prompt, Args: []string{"a\x00b"}},
		"oversize arg":    {Mode: valid.Mode, Prompt: valid.Prompt, Args: []string{strings.Repeat("a", runIntentArgBytes+1)}},
		"too many args":   {Mode: valid.Mode, Prompt: valid.Prompt, Args: make([]string, runIntentArgCount+1)},
	}
	for name, intent := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := OwnRunIntent(&intent); !IsCode(err, CodeInvalid) {
				t.Fatalf("invalid intent accepted: %v", err)
			}
		})
	}
	args := make([]string, 5)
	for index := range args {
		args[index] = strings.Repeat("a", runIntentArgBytes)
	}
	if _, err := OwnRunIntent(&RunIntent{Mode: valid.Mode, Prompt: valid.Prompt, Args: args}); !IsCode(err, CodeInvalid) {
		t.Fatalf("aggregate argument budget accepted: %v", err)
	}
}

func TestRunIntentJSONRequiresExactUnambiguousKeys(t *testing.T) {
	for _, raw := range []string{
		`{"mode":"headless","prompt":"x","mode":"headless"}`,
		`{"Mode":"headless","prompt":"x"}`,
		`{"mode":"headless","Prompt":"x"}`,
		`{"mode":"headless","prompt":"x","extra":1}`,
		`{"mode":"headless","prompt":"x","args":null}`,
		`{"mode":"headless","prompt":"x","args": null}`,
		`{"mode":null,"prompt":"x"}`,
		`{"mode":"headless","prompt":null}`,
		`{"mode":"headless","prompt":"x","args":[null]}`,
	} {
		var intent RunIntent
		if err := json.Unmarshal([]byte(raw), &intent); !IsCode(err, CodeInvalid) {
			t.Fatalf("ambiguous intent %q accepted: %v", raw, err)
		}
	}
	var trailing RunIntent
	if err := json.Unmarshal([]byte(`{"mode":"headless","prompt":"x"} {"mode":"headless","prompt":"y"}`), &trailing); err == nil {
		t.Fatal("trailing JSON value accepted")
	}
	var intent RunIntent
	if err := json.Unmarshal([]byte(`{"mode":"headless","prompt":"x","args":["--model","sonnet"]}`), &intent); err != nil || len(intent.Args) != 2 {
		t.Fatalf("exact intent rejected: %#v, %v", intent, err)
	}
}
