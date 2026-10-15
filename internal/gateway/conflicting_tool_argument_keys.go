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

package gateway

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	// conflictingToolArgumentsRuleID is the conservative finding of a shell
	// or file-write tool call whose arguments name one field more than once.
	conflictingToolArgumentsRuleID = "TOOL-ARGS-CONFLICT"
	conflictingToolArgumentsTitle  = "Conflicting tool arguments: more than one key names the same argument, so the call cannot be verified"
	// maxConflictingToolArgumentCandidates bounds the single-key calls one
	// call is judged as.
	maxConflictingToolArgumentCandidates = 16
)

// conflictingToolArguments is a tool call whose analysis is ambiguous
// because two of its argument keys name the same field (GAP-0678).
type conflictingToolArguments struct {
	// candidates are the call with each such field named once, for every
	// key and value it was given.
	candidates []actionfacts.Input
	// shellOrWrite is set when a candidate is a complete shell or
	// file-write call.
	shellOrWrite bool
}

// conflictingToolArgumentKeys reports a tool call whose argument object
// carries two keys for one field: keys equal but for letter case (command
// and Command, filePath and filepath, content and Content), or two of the
// target keys file_path, filePath and path. ActionFacts folds those keys
// onto one field (ambiguous, conflicting sources) or, in a closed argument
// contract, reads the second key as an unknown one (partial). Such a call
// cannot be verified.
//
// It applies only when at least one candidate, the call with each such
// field named once, is a complete analysis: the extra key alone made the
// call uncertain, and the rest is a reviewed argument contract. Every other
// ambiguous or partial call keeps its result.
func conflictingToolArgumentKeys(input actionfacts.Input, facts actionfacts.Facts) (conflictingToolArguments, bool) {
	if !conflictingToolArgumentStatus(facts.Parse) ||
		input.Command != "" || len(input.Argv) != 0 || len(input.Args) == 0 {
		return conflictingToolArguments{}, false
	}
	object, ok := decodeExactTrustedJSONObject(input.Args)
	if !ok {
		return conflictingToolArguments{}, false
	}
	groups := make(map[string][]string, len(object))
	for key := range object {
		field := conflictingToolArgumentField(key)
		groups[field] = append(groups[field], key)
	}
	shared := make(map[string]json.RawMessage, len(object))
	var conflicting [][]string
	for _, keys := range groups {
		if len(keys) == 1 {
			shared[keys[0]] = object[keys[0]]
			continue
		}
		sort.Strings(keys)
		conflicting = append(conflicting, keys)
	}
	if len(conflicting) == 0 {
		return conflictingToolArguments{}, false
	}
	sort.Slice(conflicting, func(i, j int) bool { return conflicting[i][0] < conflicting[j][0] })

	// Each field is named by each of its keys with each of its values, so a
	// value is judged under the key the reviewed contract reads.
	choices := []map[string]json.RawMessage{shared}
	total := 1
	for _, keys := range conflicting {
		total *= len(keys) * len(keys)
		if total > maxConflictingToolArgumentCandidates {
			break
		}
	}
	if total <= maxConflictingToolArgumentCandidates {
		for _, keys := range conflicting {
			next := make([]map[string]json.RawMessage, 0, len(choices)*len(keys)*len(keys))
			for _, choice := range choices {
				for _, name := range keys {
					for _, source := range keys {
						next = append(next, withArgument(choice, name, object[source]))
					}
				}
			}
			choices = next
		}
	} else {
		// Too many fields to try every pairing: each key keeps its own value.
		widest := 0
		for _, keys := range conflicting {
			widest = max(widest, len(keys))
		}
		next := make([]map[string]json.RawMessage, 0, widest)
		for index := range widest {
			choice := shared
			for _, keys := range conflicting {
				key := keys[min(index, len(keys)-1)]
				choice = withArgument(choice, key, object[key])
			}
			next = append(next, choice)
		}
		choices = next
	}

	var result conflictingToolArguments
	complete := false
	seen := make(map[string]struct{}, len(choices))
	for _, choice := range choices {
		raw, err := json.Marshal(choice)
		if err != nil {
			continue
		}
		if _, duplicate := seen[string(raw)]; duplicate {
			continue
		}
		seen[string(raw)] = struct{}{}
		candidate := input
		candidate.Args = raw
		result.candidates = append(result.candidates, candidate)
		analysis := actionfacts.Analyze(candidate)
		if !analysis.Authoritative() {
			continue
		}
		complete = true
		// A complete analysis of a command argument is an execution tool:
		// ActionFacts reads command text only for one.
		if (len(analysis.Commands) > 0 && hasCommandArgument(candidate.Args)) ||
			slices.ContainsFunc(analysis.Paths, writeClassPathFact) {
			result.shellOrWrite = true
		}
	}
	return result, complete
}

// conflictingToolArgumentStatus is the analysis an extra key for a field
// leaves: ambiguous with conflicting sources, or partial with only unknown
// operands.
func conflictingToolArgumentStatus(parse actionfacts.ParseResult) bool {
	switch parse.Status {
	case actionfacts.StatusAmbiguous:
		return slices.Contains(parse.Issues, actionfacts.IssueConflictingSources)
	case actionfacts.StatusPartial:
		return len(parse.Issues) > 0 && !slices.ContainsFunc(parse.Issues, func(issue actionfacts.IssueCode) bool {
			return issue != actionfacts.IssueUnknownOperandGrammar
		})
	}
	return false
}

func hasCommandArgument(args json.RawMessage) bool {
	object, ok := decodeExactTrustedJSONObject(args)
	if !ok {
		return false
	}
	for key := range object {
		if strings.EqualFold(key, "command") {
			return true
		}
	}
	return false
}

// conflictingToolArgumentField is the field an argument key names for the
// conflict check: its lower-case form, with the file target keys as one.
func conflictingToolArgumentField(key string) string {
	field := strings.ToLower(key)
	switch field {
	case "filepath", "file_path", "file-path", "path":
		return "path"
	}
	return field
}

func withArgument(base map[string]json.RawMessage, key string, value json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(base)+1)
	for name, existing := range base {
		out[name] = existing
	}
	out[key] = value
	return out
}

func writeClassPathFact(path actionfacts.PathFact) bool {
	switch path.Access {
	case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
		return true
	}
	return false
}

// dispatchConflictingToolArguments judges a call with conflicting argument
// keys as each of its candidates, so a dangerous value under either key
// gets its own rule finding. A shell or file-write call also takes a
// conservative CRITICAL finding: the call itself cannot be verified, so it
// never falls through to allow. Like every finding, it only blocks where the
// call is enforcement-capable (observe mode records would_block).
func dispatchConflictingToolArguments(
	parent context.Context,
	request trustedActionRequest,
	conflict conflictingToolArguments,
) []RuleFinding {
	var findings []RuleFinding
	for _, candidate := range conflict.candidates {
		single := request
		single.Input = candidate
		single.LegacyText = string(candidate.Args)
		single.record, single.recordTelemetry = nil, nil
		findings = append(findings, dispatchTrustedAction(parent, single)...)
	}
	findings = deduplicateTrustedActionFindings(findings)
	if !conflict.shellOrWrite {
		return findings
	}
	enforcement := findingEnforcementAllowed
	if !request.EnforcementCapable {
		enforcement = findingEnforcementDetectionOnly
	}
	return append(findings, RuleFinding{
		RuleID:      conflictingToolArgumentsRuleID,
		Title:       conflictingToolArgumentsTitle,
		Severity:    "CRITICAL",
		Confidence:  1,
		Tags:        []string{"tool-arguments"},
		LineNumber:  1,
		enforcement: enforcement,
	})
}
