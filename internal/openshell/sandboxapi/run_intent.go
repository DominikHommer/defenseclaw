// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	runIntentPromptBytes = 64 << 10
	runIntentArgBytes    = 4 << 10
	runIntentArgsBytes   = 16 << 10
	runIntentArgCount    = 32
)

// RunIntent is client data for one native headless launch. It contains no
// executable, environment, runtime identity or policy authority. A qualified
// host producer must derive the actual argv from its held harness and policy;
// the literal arguments never become a command by themselves.
type RunIntent struct {
	Mode   string   `json:"mode"`
	Prompt string   `json:"prompt"`
	Args   []string `json:"args,omitempty"`
}

func invalidRunIntent() error {
	// A prompt or argument may contain private user data. Never echo values in
	// an API error, including malformed JSON and budget refusals.
	return Errorf(CodeInvalid, "invalid native run intent")
}

// Validate applies a fixed byte budget before a native producer sees intent.
// Provider-specific flags remain for that producer to refuse or compile.
func (i RunIntent) Validate() error {
	if i.Mode != "headless" || len(i.Prompt) == 0 || len(i.Prompt) > runIntentPromptBytes ||
		!utf8.ValidString(i.Prompt) || strings.TrimSpace(i.Prompt) == "" || strings.ContainsRune(i.Prompt, 0) ||
		len(i.Args) > runIntentArgCount {
		return invalidRunIntent()
	}
	budget := 0
	for _, arg := range i.Args {
		if len(arg) == 0 || len(arg) > runIntentArgBytes || !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) {
			return invalidRunIntent()
		}
		budget += len(arg)
		if budget > runIntentArgsBytes {
			return invalidRunIntent()
		}
	}
	return nil
}

// OwnRunIntent validates and copies the optional client intent. Manager.Create
// calls this before any producer callback can observe caller-backed slices.
func OwnRunIntent(input *RunIntent) (*RunIntent, error) {
	if input == nil {
		return nil, nil
	}
	if err := input.Validate(); err != nil {
		return nil, err
	}
	owned := *input
	owned.Args = slices.Clone(input.Args)
	return &owned, nil
}

// UnmarshalJSON refuses unknown, duplicate, case-aliased and null fields.
// The enclosing request decoder alone does not reject all of those forms.
func (i *RunIntent) UnmarshalJSON(raw []byte) error {
	if i == nil || !utf8.Valid(raw) || len(raw) > runIntentPromptBytes+runIntentArgsBytes+4096 {
		return invalidRunIntent()
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return invalidRunIntent()
	}
	keys := map[string]bool{"mode": true, "prompt": true, "args": true}
	seen := map[string]bool{}
	for dec.More() {
		token, err := dec.Token()
		key, ok := token.(string)
		if err != nil || !ok || !keys[key] || seen[key] {
			return invalidRunIntent()
		}
		seen[key] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalidRunIntent()
		}
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') || !seen["mode"] || !seen["prompt"] {
		return invalidRunIntent()
	}
	if dec.Decode(new(any)) != io.EOF {
		return invalidRunIntent()
	}
	var value struct {
		Mode   string   `json:"mode"`
		Prompt string   `json:"prompt"`
		Args   []string `json:"args"`
	}
	if json.Unmarshal(raw, &value) != nil {
		return invalidRunIntent()
	}
	i.Mode, i.Prompt, i.Args = value.Mode, value.Prompt, value.Args
	return i.Validate()
}
