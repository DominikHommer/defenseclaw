// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func shellBraceWordValues(word *syntax.Word) ([]string, bool) {
	if word == nil {
		return nil, false
	}
	copyWord := *word
	copyWord.Parts = append([]syntax.WordPart(nil), word.Parts...)
	if !syntax.SplitBraces(&copyWord) {
		return nil, false
	}
	var expand func([]syntax.WordPart) ([]string, bool)
	expand = func(parts []syntax.WordPart) ([]string, bool) {
		values := []string{""}
		for _, part := range parts {
			options := []string{}
			switch part := part.(type) {
			case *syntax.Lit:
				options = append(options, part.Value)
			case *syntax.SglQuoted:
				options = append(options, part.Value)
			case *syntax.BraceExp:
				if part.Sequence {
					var ok bool
					options, ok = shellBraceSequenceValues(part)
					if !ok {
						return nil, false
					}
				} else {
					for _, element := range part.Elems {
						items, ok := expand(element.Parts)
						if !ok || len(options)+len(items) > maxAnalysisExpansionWidth {
							return nil, false
						}
						options = append(options, items...)
					}
				}
			default:
				return nil, false
			}
			if len(options) == 0 || len(values) > maxAnalysisExpansionWidth/len(options) {
				return nil, false
			}
			next := make([]string, 0, len(values)*len(options))
			for _, value := range values {
				for _, option := range options {
					next = append(next, value+option)
				}
			}
			values = next
		}
		return values, true
	}
	return expand(copyWord.Parts)
}

func shellBraceSequenceValues(brace *syntax.BraceExp) ([]string, bool) {
	width := shellBraceSequenceWidth(brace)
	if width <= 0 || width > maxAnalysisExpansionWidth {
		return nil, false
	}
	first, last := brace.Elems[0].Lit(), brace.Elems[1].Lit()
	start, firstErr := strconv.ParseInt(first, 10, 64)
	end, lastErr := strconv.ParseInt(last, 10, 64)
	if firstErr != nil || lastErr != nil {
		if len(first) != 1 || len(last) != 1 {
			return nil, false
		}
		start, end = int64(first[0]), int64(last[0])
	}
	step := int64(1)
	if len(brace.Elems) == 3 {
		var err error
		step, err = strconv.ParseInt(brace.Elems[2].Lit(), 10, 64)
		if err != nil || step == 0 || step == -step {
			return nil, false
		}
		if step < 0 {
			step = -step
		}
	}
	pad := firstErr == nil && lastErr == nil && (len(first) > 1 && first[0] == '0' || len(last) > 1 && last[0] == '0')
	digits := len(strings.TrimPrefix(first, "-"))
	if len(strings.TrimPrefix(last, "-")) > digits {
		digits = len(strings.TrimPrefix(last, "-"))
	}
	values := make([]string, 0, width)
	for index := 0; index < width; index++ {
		value := start + int64(index)*step
		if end < start {
			value = start - int64(index)*step
		}
		if firstErr != nil {
			values = append(values, string(rune(value)))
		} else if pad {
			values = append(values, fmt.Sprintf("%0*d", digits, value))
		} else {
			values = append(values, strconv.FormatInt(value, 10))
		}
	}
	return values, true
}

func shellCandidateFiniteValues(word *syntax.Word, home, cwd string, base shellVariables,
	candidates *shellVariableCandidateSet) ([]string, bool) {
	if word == nil || candidates == nil || candidates.allUnknown {
		return nil, false
	}
	names, dynamic := shellWordDynamicParamNames(word, home)
	if dynamic || len(names) == 0 {
		return nil, false
	}
	vars := base.clone()
	if vars == nil {
		vars = shellVariables{}
	}
	values := make([]string, 0, len(names))
	seen := map[string]bool{}
	steps := 0
	var expand func(int) bool
	expand = func(index int) bool {
		if index == len(names) {
			value, ok := shellStaticWordWithKnownCalls(word, home, cwd, vars, shellVariablePoison{})
			if !ok {
				return false
			}
			if !seen[value] {
				seen[value] = true
				values = append(values, value)
			}
			return true
		}
		name := names[index]
		options := candidates.values[name]
		if candidates.unknown[name] || len(options) == 0 {
			return false
		}
		for _, option := range options {
			steps++
			if steps > maxAnalysisExpansionWidth {
				return false
			}
			vars[name] = option
			if !expand(index + 1) {
				return false
			}
		}
		delete(vars, name)
		return true
	}
	return values, expand(0)
}
