// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"regexp"
	"slices"
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
// call acts on. The path may sit in a string; the write call must start in
// code (MaskPythonStrings), since a call spelled in a string or in the
// literal text of an f-string runs nothing, unless the code may run a string
// (PythonStringsMayRun), when the masked text counts whole as before.
func pythonPathWriteMatch(rule *regexp.Regexp, source string) []int {
	code := MaskPythonCommentsAndDocstrings(source)
	calls := MaskPythonStrings(source)
	if PythonStringsMayRun(calls) {
		calls = code
	}
	lines := strings.Split(code, "\n")
	callLines := strings.Split(calls, "\n")
	if len(callLines) != len(lines) {
		callLines = lines
	}
	for _, hit := range rule.FindAllStringIndex(code, -1) {
		lineNo := strings.Count(code[:hit[0]], "\n")
		if lineNo >= len(lines) {
			continue
		}
		lineStart := hit[0] - strings.LastIndex(code[:hit[0]], "\n") - 1
		line := lines[lineNo]
		if pythonLineWritesPath(line, callLines[lineNo], lineStart, hit[1]-hit[0]) {
			return hit
		}
		assign := pythonAssignment.FindStringSubmatch(line)
		if len(assign) != 2 || strings.Index(line, "=") > lineStart {
			continue
		}
		// A path assigned to a name is a write when a later statement uses
		// that name as the path argument. This covers Path.home()/"name"
		// followed by open(target, "a"), the common skill-script form.
		for offset, later := range lines[lineNo+1:] {
			if pythonLineWritesName(later, callLines[lineNo+1+offset], assign[1]) {
				return hit
			}
		}
	}
	return nil
}

// pythonLineWritesPath reports whether a write call on line acts on the
// path at column. calls is the line with its string text blanked
// (MaskPythonStrings): a write call must start in code.
func pythonLineWritesPath(line, calls string, column, width int) bool {
	if column < 0 || column+width > len(line) || len(calls) != len(line) {
		return false
	}
	// The path must be inside the argument list, not elsewhere on a line
	// that happens to have another write call.
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			if pythonCodeAt(line, calls, call[0]) && pythonCallContains(line, call[0], column, column+width) {
				return true
			}
		}
	}
	// pathlib's mutation methods act on the preceding Path object.
	for _, path := range pythonPathCall.FindAllStringIndex(line, -1) {
		end := pythonCallEnd(line, path[1]-1)
		if end >= column+width && column >= path[1] && pythonCodeAt(line, calls, path[0]) &&
			pythonWriteMethod.MatchString(strings.TrimSpace(calls[end+1:])) {
			return true
		}
	}
	return false
}

// pythonLineWritesName reports whether a write call in the code of line
// (calls, the line with its string text blanked) acts on the variable name.
func pythonLineWritesName(line, calls, name string) bool {
	if len(calls) != len(line) {
		return false
	}
	for _, re := range []*regexp.Regexp{pythonModuleWrite, pythonWriteOpen} {
		for _, call := range re.FindAllStringIndex(line, -1) {
			if !pythonCodeAt(line, calls, call[0]) {
				continue
			}
			end := pythonCallEnd(line, strings.IndexByte(line[call[0]:], '(')+call[0])
			if end > call[0] && containsPythonName(calls[call[0]:end], name) {
				return true
			}
		}
	}
	for _, method := range pythonWriteMethod.FindAllStringIndex(line, -1) {
		if pythonCodeAt(line, calls, method[0]) && containsPythonName(calls[:method[0]], name) {
			return true
		}
	}
	return false
}

// pythonCodeAt reports whether text[i] is code: MaskPythonStrings kept it.
func pythonCodeAt(text, calls string, i int) bool {
	return i >= 0 && i < len(text) && i < len(calls) && text[i] != ' ' && calls[i] == text[i]
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

// MaskPythonStrings blanks the comments of Python source and the text of
// every string literal in place, quotes included, keeping the replacement
// fields of f- and t-strings (whose own strings are blanked too): what is
// left is the code that runs. A call spelled inside a string, or in the
// literal text of a one-line f-string, is data, not a call. Source whose
// strings the scan cannot follow is returned unmasked (fail closed).
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
			var fields [][2]int
			end, ok := pythonStringEnd(out, i, depth, &fields)
			if !ok || end > to {
				return false
			}
			text := i
			for _, field := range fields {
				blankPythonText(out[text:field[0]])
				if !maskPythonStrings(out, field[0]+1, field[1]-1, depth+1) {
					return false
				}
				text = field[1]
			}
			blankPythonText(out[text:end])
			i = end
		default:
			i++
		}
	}
	return true
}

// pythonStringRunFragments are the names (lower case, matched inside an
// identifier) through which code can turn string text into code that runs,
// or reach a string that does not run: dynamic evaluation and name lookup,
// child processes, serializers that call, introspection of code, frames and
// docstrings, the program's own command line, and a file the code writes
// (and may import or run later).
var pythonStringRunFragments = []string{
	"exec", "eval", "compile", "getattr", "attrgetter", "methodcaller",
	"globals", "locals", "vars", "__dict__", "__import__", "importlib",
	"import_module", "builtins", "runpy", "pkgutil", "pydoc", "loader",
	"subprocess", "system", "popen", "spawn", "startfile", "createprocess",
	"winapi", "ctypes", "cffi", "marshal", "pickle", "shelve", "yaml",
	"interact", "timeit", "profile", "trace", "breakpoint", "doc", "__code__",
	"co_consts", "co_code", "frame", "inspect", "modules", "subclasses",
	"__base", "argv", "cmdline", "commandline", "procargs", "psutil",
	"sysctl", "linecache", "source", "write", "open", "dump", "copy",
	"logging", "handler",
}

// pythonStringRunNames are short names matched whole.
var pythonStringRunNames = map[string]bool{
	"code": true, "pty": true, "pdb": true, "bdb": true, "gc": true, "mro": true,
}

// PythonStringsMayRun reports whether code, Python source masked with
// MaskPythonStrings, may run or read the text of one of its strings or
// docstrings: a name of pythonStringRunFragments or pythonStringRunNames
// appears in it. A name in an import statement does not count when no name
// that statement binds is used elsewhere: an unused import runs nothing.
func PythonStringsMayRun(code string) bool {
	names := pythonName.FindAllStringIndex(code, -1)
	unused := pythonUnusedImports(code, names)
	for _, name := range names {
		if !pythonStringRunName(strings.ToLower(code[name[0]:name[1]])) {
			continue
		}
		if !slices.ContainsFunc(unused, func(span [2]int) bool {
			return name[0] >= span[0] && name[1] <= span[1]
		}) {
			return true
		}
	}
	return false
}

func pythonStringRunName(name string) bool {
	if pythonStringRunNames[name] {
		return true
	}
	for _, fragment := range pythonStringRunFragments {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

// pythonUnusedImports returns the spans of the import statements of code
// (strings blanked) none of whose bound names is used outside the statement.
// A statement ends at a newline, ";" or ":" outside brackets ("if x: import
// y"). "from m import *" binds unknown names, so it is never unused.
func pythonUnusedImports(code string, names [][]int) [][2]int {
	var unused [][2]int
	depth, start := 0, 0
	for i := 0; i <= len(code); i++ {
		if i < len(code) {
			switch c := code[i]; c {
			case '(', '[', '{':
				depth++
				continue
			case ')', ']', '}':
				depth = max(depth-1, 0)
				continue
			case '\n', ';', ':':
				if depth > 0 || c == '\n' && i > 0 && code[i-1] == '\\' {
					continue
				}
			default:
				continue
			}
		}
		if bound, ok := pythonImportBindings(code[start:i]); ok && !pythonNamesUsed(code, names, bound, start, i) {
			unused = append(unused, [2]int{start, i})
		}
		start = i + 1
	}
	return unused
}

// pythonImportBindings returns the names an import statement binds, and
// false when statement is not an import or binds unknown names.
func pythonImportBindings(statement string) ([]string, bool) {
	words := strings.Fields(strings.NewReplacer("(", " ", ")", " ", ",", " , ", "\\", " ").Replace(statement))
	var items []string
	switch {
	case len(words) >= 2 && words[0] == "import":
		items = words[1:]
	case len(words) >= 4 && words[0] == "from" && slices.Contains(words[2:], "import"):
		items = words[slices.Index(words, "import")+1:]
	default:
		return nil, false
	}
	var bound []string
	for len(items) > 0 {
		end := slices.Index(items, ",")
		if end < 0 {
			end = len(items)
		}
		item := items[:end]
		switch {
		case len(item) == 1:
			bound = append(bound, strings.SplitN(item[0], ".", 2)[0])
		case len(item) == 3 && item[1] == "as":
			bound = append(bound, item[2])
		default:
			return nil, false
		}
		if end == len(items) {
			break
		}
		items = items[end+1:]
		if len(items) == 0 {
			return nil, false // a trailing comma
		}
	}
	for _, name := range bound {
		if name == "*" || !pythonName.MatchString(name) || pythonName.FindString(name) != name {
			return nil, false
		}
	}
	return bound, len(bound) > 0
}

// pythonNamesUsed reports whether a name of bound appears in code outside
// code[from:to].
func pythonNamesUsed(code string, names [][]int, bound []string, from, to int) bool {
	for _, name := range names {
		if name[0] >= from && name[1] <= to {
			continue
		}
		if slices.Contains(bound, code[name[0]:name[1]]) {
			return true
		}
	}
	return false
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
