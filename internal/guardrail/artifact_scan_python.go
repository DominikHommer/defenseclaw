// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"regexp"
	"strings"
)

// Python path rules describe a write, not a mention. Keep the original byte
// offsets for finding locations while ignoring comments and docstrings.
var pythonAssignment = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z_0-9]*)\s*=`)
var pythonWriteMethod = regexp.MustCompile(`\.(?:write_text|write_bytes|unlink|rmdir|rename|touch)\s*\(`)
var pythonModuleWrite = regexp.MustCompile(`\b(?:os\.(?:remove|unlink|rename|replace|truncate|rmdir|removedirs)|shutil\.(?:move|rmtree|copy|copy2|copyfile|copytree))\s*\(`)
var pythonWriteOpen = regexp.MustCompile(`\bopen\s*\([^\n)]*,\s*["'][rbtU]*[wax+]`)
var pythonPathCall = regexp.MustCompile(`\bPath\s*\(`)
var pythonName = regexp.MustCompile(`[A-Za-z_][A-Za-z_0-9]*`)

// pythonPathWriteMatch returns the first match of rule, a path, that a write
// call of source acts on, with comments and triple-quoted strings blanked
// (MaskPythonCommentsAndDocstrings). A write call spelled in a one-line
// string counts: whether a string runs depends on the modules the script
// loads, and the import path that supplies them (PYTHONPATH, a module beside
// the script, a sitecustomize) belongs to whoever runs the script later, not
// to the scan.
func pythonPathWriteMatch(rule *regexp.Regexp, source string) []int {
	code := MaskPythonCommentsAndDocstrings(source)
	lines := strings.Split(code, "\n")
	for _, hit := range rule.FindAllStringIndex(code, -1) {
		lineNo := strings.Count(code[:hit[0]], "\n")
		if lineNo >= len(lines) {
			continue
		}
		lineStart := hit[0] - strings.LastIndex(code[:hit[0]], "\n") - 1
		line := lines[lineNo]
		if pythonLineWritesPath(line, lineStart, hit[1]-hit[0]) {
			return hit
		}
		assign := pythonAssignment.FindStringSubmatch(line)
		if len(assign) != 2 || strings.Index(line, "=") > lineStart {
			continue
		}
		// A path assigned to a name is a write when a later statement uses
		// that name as the path argument. This covers Path.home()/"name"
		// followed by open(target, "a"), the common skill-script form.
		for _, later := range lines[lineNo+1:] {
			if pythonLineWritesName(later, assign[1]) {
				return hit
			}
		}
	}
	return nil
}

func pythonLineWritesPath(line string, column, width int) bool {
	if column < 0 || column+width > len(line) {
		return false
	}
	// The path must be inside the argument list, not elsewhere on a line
	// that happens to have another write call.
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			if pythonCallContains(line, call[0], column, column+width) {
				return true
			}
		}
	}
	// pathlib's mutation methods act on the preceding Path object.
	for _, path := range pythonPathCall.FindAllStringIndex(line, -1) {
		end := pythonCallEnd(line, path[1]-1)
		if end >= column+width && column >= path[1] &&
			pythonWriteMethod.MatchString(strings.TrimSpace(line[end+1:])) {
			return true
		}
	}
	return false
}

func pythonLineWritesName(line, name string) bool {
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			end := pythonCallEnd(line, strings.IndexByte(line[call[0]:], '(')+call[0])
			if end > call[0] && containsPythonName(line[call[0]:end], name) {
				return true
			}
		}
	}
	for _, method := range pythonWriteMethod.FindAllStringIndex(line, -1) {
		if containsPythonName(line[:method[0]], name) {
			return true
		}
	}
	return false
}

func containsPythonName(text, name string) bool {
	for _, pos := range pythonName.FindAllStringIndex(text, -1) {
		if text[pos[0]:pos[1]] == name {
			return true
		}
	}
	return false
}

func pythonCallContains(line string, callStart, matchStart, matchEnd int) bool {
	openRel := strings.IndexByte(line[callStart:], '(')
	if openRel < 0 {
		return false
	}
	open := callStart + openRel
	end := pythonCallEnd(line, open)
	return end >= matchEnd && matchStart > open
}

func pythonCallEnd(line string, open int) int {
	if open < 0 || open >= len(line) || line[open] != '(' {
		return -1
	}
	depth := 0
	var quote byte
	escaped := false
	for i := open; i < len(line); i++ {
		switch c := line[i]; {
		case quote != 0:
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// MaskPythonCommentsAndDocstrings blanks the comments and the triple-quoted
// strings of Python source in place, so matches keep their offsets: they can
// mention paths without executing a write. An f- or t-string runs the
// expressions of its replacement fields, so those are kept and its literal
// text is blanked: the text around the fields, the literal text of a format
// spec (f"{x:spec}", whose nested fields run), a conversion (!r) and a
// self-documenting "=" (f"{x=}"). Source whose strings the scan cannot
// follow (an unclosed string or field, nesting past pythonMaxStringNesting) is
// returned unmasked: blanking from a wrong string boundary could hide code.
func MaskPythonCommentsAndDocstrings(source string) string {
	out := []byte(source)
	for i := 0; i < len(out); {
		switch out[i] {
		case '#':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case '\'', '"':
			var exprs [][2]int
			end, ok := pythonStringEnd(out, i, 0, &exprs)
			if !ok {
				return source
			}
			if pythonTripleQuoteAt(out, i) {
				// Blank the literal text around the field expressions, which run.
				from := i
				for _, expr := range exprs {
					blankPythonText(out[from:expr[0]])
					from = expr[1]
				}
				blankPythonText(out[from:end])
			}
			i = end
		default:
			i++
		}
	}
	return string(out)
}

// MaskPythonStrings blanks the comments of Python source and the text of
// every string literal in place, quotes included, keeping the expressions of
// the replacement fields of f- and t-strings (whose own strings are blanked
// too; format spec text is literal text): what is left is the code that
// runs. A call spelled inside a string, or in the literal text of a one-line
// f-string, is data, not a call. Source whose strings the scan cannot follow
// is returned unmasked (fail closed).
func MaskPythonStrings(source string) string {
	out := []byte(source)
	if !maskPythonStrings(out, 0, len(out), 0) {
		return source
	}
	return string(out)
}

func maskPythonStrings(out []byte, from, to, depth int) bool {
	for i := from; i < to; {
		switch out[i] {
		case '#':
			for i < to && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case '\'', '"':
			var exprs [][2]int
			end, ok := pythonStringEnd(out, i, depth, &exprs)
			if !ok || end > to {
				return false
			}
			text := i
			for _, expr := range exprs {
				blankPythonText(out[text:expr[0]])
				if !maskPythonStrings(out, expr[0], expr[1], depth+1) {
					return false
				}
				text = expr[1]
			}
			blankPythonText(out[text:end])
			i = end
		default:
			i++
		}
	}
	return true
}

// blankPythonText blanks text in place, newlines kept.
func blankPythonText(text []byte) {
	for j, c := range text {
		if c != '\n' {
			text[j] = ' '
		}
	}
}

// pythonMaxStringNesting bounds strings inside replacement fields inside
// strings (f"{f'{x}'}").
const pythonMaxStringNesting = 32

func pythonTripleQuoteAt(src []byte, i int) bool {
	return i+2 < len(src) && src[i+1] == src[i] && src[i+2] == src[i]
}

// pythonFormatString reports whether the string literal whose quote is at
// src[i] has an f or t prefix (f"x", rf'x', t"""x"""), whose fields run.
func pythonFormatString(src []byte, i int) bool {
	start := i
	for start > 0 && start > i-2 && pythonLetter(src[start-1]) {
		start--
	}
	if start > 0 && (pythonLetter(src[start-1]) || src[start-1] == '_' ||
		src[start-1] >= '0' && src[start-1] <= '9') {
		return false // the end of a longer name, not a prefix
	}
	switch strings.ToLower(string(src[start:i])) {
	case "f", "fr", "rf", "t", "tr", "rt":
		return true
	}
	return false
}

func pythonLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// pythonStringEnd returns the offset just past the string literal whose
// opening quote is at src[i], following the replacement fields of an f- or
// t-string, whose expressions may hold strings with the same quotes
// (Python 3.12). When exprs is not nil, the span of the expression of each
// replacement field of this string, and of each field nested in a format spec,
// is appended to it in order (pythonFieldEnd): the code of the string.
func pythonStringEnd(src []byte, i, depth int, exprs *[][2]int) (int, bool) {
	if depth > pythonMaxStringNesting {
		return 0, false
	}
	quote, triple, format := src[i], pythonTripleQuoteAt(src, i), pythonFormatString(src, i)
	j := i + 1
	if triple {
		j = i + 3
	}
	for j < len(src) {
		c := src[j]
		switch {
		case c == '\\':
			if format && j+1 < len(src) && src[j+1] == '{' {
				j++ // a backslash does not escape a field
				continue
			}
			j += 2
			continue
		case c == quote && !triple:
			return j + 1, true
		case c == quote && pythonTripleQuoteAt(src, j):
			return j + 3, true
		case c == '\n' && !triple:
			return 0, false
		case format && c == '{':
			if j+1 < len(src) && src[j+1] == '{' {
				j += 2
				continue
			}
			end, ok := pythonFieldEnd(src, j+1, depth+1, exprs)
			if !ok {
				return 0, false
			}
			j = end
			continue
		}
		j++
	}
	return 0, false
}

// pythonFieldEnd returns the offset just past the "}" that closes the
// replacement field whose expression starts at src[j]. When exprs is not nil,
// it appends the span of the expression (pythonFieldExpression) and of the
// expressions of the fields nested in its format spec.
func pythonFieldEnd(src []byte, j, depth int, exprs *[][2]int) (int, bool) {
	start, brackets, conversion := j, 0, -1
	for j < len(src) {
		switch src[j] {
		case '\'', '"':
			end, ok := pythonStringEnd(src, j, depth, nil)
			if !ok {
				return 0, false
			}
			j = end
			continue
		case '#':
			for j < len(src) && src[j] != '\n' {
				j++
			}
			continue
		case '(', '[', '{':
			brackets++
		case ')', ']':
			brackets--
		case '!':
			if brackets == 0 && conversion < 0 && (j+1 >= len(src) || src[j+1] != '=') {
				conversion = j // !r, !s or !a: text, not code
			}
		case '}':
			if brackets == 0 {
				pythonFieldExpression(src, start, conversion, j, exprs)
				return j + 1, true
			}
			brackets--
		case ':':
			if brackets == 0 {
				pythonFieldExpression(src, start, conversion, j, exprs)
				return pythonFormatSpecEnd(src, j+1, depth, exprs)
			}
		}
		j++
	}
	return 0, false
}

// pythonFieldExpression appends to exprs (when not nil) the span of the
// expression of a replacement field from src[start] to its conversion, or to
// end when it has none, less a self-documenting "=" (f"{x=}" prints the text
// "x="; x= is not an assignment).
func pythonFieldExpression(src []byte, start, conversion, end int, exprs *[][2]int) {
	if exprs == nil {
		return
	}
	if conversion >= 0 {
		end = conversion
	}
	last := end
	for last > start && strings.IndexByte(" \t\r\n", src[last-1]) >= 0 {
		last--
	}
	if last > start && src[last-1] == '=' && (last-1 == start || strings.IndexByte("=!<>", src[last-2]) < 0) {
		end = last - 1
	}
	*exprs = append(*exprs, [2]int{start, end})
}

// pythonFormatSpecEnd returns the offset just past the "}" that closes a
// field whose format spec (literal text with nested fields) starts at src[j],
// appending the expressions of the nested fields to exprs (when not nil).
func pythonFormatSpecEnd(src []byte, j, depth int, exprs *[][2]int) (int, bool) {
	for j < len(src) {
		switch src[j] {
		case '{':
			end, ok := pythonFieldEnd(src, j+1, depth+1, exprs)
			if !ok {
				return 0, false
			}
			j = end
			continue
		case '}':
			return j + 1, true
		}
		j++
	}
	return 0, false
}
