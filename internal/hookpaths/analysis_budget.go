// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strconv"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

const (
	maxAnalysisNodes          = 16384
	maxAnalysisAssignments    = 384
	maxAnalysisExpansionWidth = 8192
	maxAnalysisBytes          = 16 << 20
	maxAnalysisParseTime      = 500 * time.Millisecond
)

type shellAnalysisBudget struct {
	deadline    time.Time
	nodes       int
	assignments int
	bytes       int
	limited     bool
}

func newShellAnalysisBudget() shellAnalysisBudget {
	return shellAnalysisBudget{deadline: time.Now().Add(maxAnalysisParseTime)}
}

func (budget *shellAnalysisBudget) check(file *syntax.File) bool {
	if file == nil || budget.bytes > maxAnalysisBytes || time.Now().After(budget.deadline) {
		return false
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if budget.limited {
			return false
		}
		budget.nodes++
		budget.bytes += 128
		if stmt, ok := node.(*syntax.Stmt); ok {
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) == 0 && len(call.Assigns) > 0 {
				budget.assignments++
			}
		}
		if word, ok := node.(*syntax.Word); ok {
			copyWord := *word
			copyWord.Parts = append([]syntax.WordPart(nil), word.Parts...)
			syntax.SplitBraces(&copyWord)
			width := shellWordExpansionWidth(copyWord.Parts)
			if width > maxAnalysisExpansionWidth {
				budget.limited = true
			} else {
				budget.bytes += width * 32
			}
		}
		if budget.nodes > maxAnalysisNodes || budget.assignments > maxAnalysisAssignments ||
			budget.bytes > maxAnalysisBytes || budget.nodes%64 == 0 && time.Now().After(budget.deadline) {
			budget.limited = true
		}
		return !budget.limited
	})
	return !budget.limited && !time.Now().After(budget.deadline)
}

func shellWordExpansionWidth(parts []syntax.WordPart) int {
	width := 1
	for _, part := range parts {
		brace, ok := part.(*syntax.BraceExp)
		if !ok {
			continue
		}
		choices := len(brace.Elems)
		if brace.Sequence {
			choices = shellBraceSequenceWidth(brace)
		} else {
			choices = 0
			for _, element := range brace.Elems {
				choices += shellWordExpansionWidth(element.Parts)
				if choices > maxAnalysisExpansionWidth {
					return maxAnalysisExpansionWidth + 1
				}
			}
		}
		if choices <= 0 || width > maxAnalysisExpansionWidth/choices {
			return maxAnalysisExpansionWidth + 1
		}
		width *= choices
	}
	return width
}

func shellBraceSequenceWidth(brace *syntax.BraceExp) int {
	if len(brace.Elems) < 2 {
		return maxAnalysisExpansionWidth + 1
	}
	from, errFrom := strconv.ParseInt(brace.Elems[0].Lit(), 10, 64)
	to, errTo := strconv.ParseInt(brace.Elems[1].Lit(), 10, 64)
	if errFrom != nil || errTo != nil {
		first, last := []rune(brace.Elems[0].Lit()), []rune(brace.Elems[1].Lit())
		if len(first) != 1 || len(last) != 1 {
			return maxAnalysisExpansionWidth + 1
		}
		from, to = int64(first[0]), int64(last[0])
	}
	step := int64(1)
	if len(brace.Elems) > 2 {
		var err error
		step, err = strconv.ParseInt(brace.Elems[2].Lit(), 10, 64)
		if err != nil || step == 0 {
			return maxAnalysisExpansionWidth + 1
		}
		if step < 0 {
			step = -step
			if step < 0 {
				return maxAnalysisExpansionWidth + 1
			}
		}
	}
	distance := uint64(from) - uint64(to)
	if to > from {
		distance = uint64(to) - uint64(from)
	}
	if distance/uint64(step) >= maxAnalysisExpansionWidth {
		return maxAnalysisExpansionWidth + 1
	}
	return int(distance/uint64(step)) + 1
}

// ShellAnalysisLimitReached reports a shell command whose bounded syntax
// analysis cannot finish within the configured work and size limits.
func ShellAnalysisLimitReached(command string) bool {
	_, _, limited := parseShellWithLimit(command)
	return limited
}
