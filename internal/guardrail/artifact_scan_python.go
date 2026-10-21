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
	for _, path := range regexp.MustCompile(`\bPath\s*\(`).FindAllStringIndex(line, -1) {
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
	for _, pos := range regexp.MustCompile(`[A-Za-z_][A-Za-z_0-9]*`).FindAllStringIndex(text, -1) {
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
// expressions of its replacement fields, so those fields are kept whole and
// only its literal text is blanked. Source whose strings the scan cannot
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
			var fields [][2]int
			end, ok := pythonStringEnd(out, i, 0, &fields)
			if !ok {
				return source
			}
			if pythonTripleQuoteAt(out, i) {
				// Blank the literal text around the fields, which run.
				from := i
				for _, field := range fields {
					blankPythonText(out[from:field[0]])
					from = field[1]
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
// (Python 3.12). When fields is not nil, the span of each replacement field
// of this string ("{" to its closing "}") is appended to it.
func pythonStringEnd(src []byte, i, depth int, fields *[][2]int) (int, bool) {
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
			end, ok := pythonFieldEnd(src, j+1, depth+1)
			if !ok {
				return 0, false
			}
			if fields != nil {
				*fields = append(*fields, [2]int{j, end})
			}
			j = end
			continue
		}
		j++
	}
	return 0, false
}

// pythonFieldEnd returns the offset just past the "}" that closes the
// replacement field whose expression starts at src[j].
func pythonFieldEnd(src []byte, j, depth int) (int, bool) {
	brackets := 0
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
		case '}':
			if brackets == 0 {
				return j + 1, true
			}
			brackets--
		case ':':
			if brackets == 0 {
				return pythonFormatSpecEnd(src, j+1, depth)
			}
		}
		j++
	}
	return 0, false
}

// pythonFormatSpecEnd returns the offset just past the "}" that closes a
// field whose format spec (literal text with nested fields) starts at src[j].
func pythonFormatSpecEnd(src []byte, j, depth int) (int, bool) {
	for j < len(src) {
		switch src[j] {
		case '{':
			end, ok := pythonFieldEnd(src, j+1, depth+1)
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
