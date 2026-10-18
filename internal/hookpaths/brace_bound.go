// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// braceWordCount returns at most limit+1. The shell expander builds every
// result before Fields returns, so callers must inspect ranges and products
// before passing a word to it.
func braceWordCount(word *syntax.Word, limit int) int {
	if word == nil || limit < 1 {
		return limit + 1
	}
	containsBrace := false
	for _, part := range word.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.Contains(lit.Value, "{") {
			containsBrace = true
			break
		}
		if _, ok := part.(*syntax.BraceExp); ok {
			containsBrace = true
			break
		}
	}
	if !containsBrace {
		return 1
	}
	copy := *word
	syntax.SplitBraces(&copy)
	return bracePartsCount(copy.Parts, limit, 0)
}

func oversizedBraceWords(file *syntax.File) bool {
	oversized := false
	syntax.Walk(file, func(node syntax.Node) bool {
		word, ok := node.(*syntax.Word)
		if ok && braceWordCount(word, MaxWriteTargets) > MaxWriteTargets {
			oversized = true
			return false
		}
		return !oversized
	})
	return oversized
}

func bracePartsCount(parts []syntax.WordPart, limit, depth int) int {
	if depth > 32 {
		return limit + 1
	}
	count := 1
	for _, part := range parts {
		brace, ok := part.(*syntax.BraceExp)
		if !ok {
			continue
		}
		choices := 0
		if brace.Sequence {
			choices = braceSequenceCount(brace, limit)
		} else {
			for _, elem := range brace.Elems {
				choices += bracePartsCount(elem.Parts, limit, depth+1)
				if choices > limit {
					return limit + 1
				}
			}
		}
		if choices == 0 || count > limit/choices {
			return limit + 1
		}
		count *= choices
	}
	return count
}

func braceSequenceCount(brace *syntax.BraceExp, limit int) int {
	if len(brace.Elems) < 2 {
		return limit + 1
	}
	left, right := brace.Elems[0].Lit(), brace.Elems[1].Lit()
	start, startErr := strconv.Atoi(left)
	end, endErr := strconv.Atoi(right)
	if startErr != nil || endErr != nil {
		if len(left) != 1 || len(right) != 1 {
			return limit + 1
		}
		start, end = int(left[0]), int(right[0])
	}
	step := 1
	if start > end {
		step = -1
	}
	if len(brace.Elems) > 2 {
		if n, err := strconv.Atoi(brace.Elems[2].Lit()); err == nil && n != 0 && (n > 0) == (step > 0) {
			step = n
		}
	}
	current := start
	for count := 1; count <= limit; count++ {
		if current == end {
			return count
		}
		next := current + step
		if step > 0 {
			if next <= current || next > end {
				return count
			}
		} else if next >= current || next < end {
			return count
		}
		current = next
	}
	return limit + 1
}
