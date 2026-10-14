// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
	"strings"
)

const literalExpressionDepth = 16

var literalExpressionCallName = regexp.MustCompile(`^[A-Za-z_][\w.]*$`)

// literalExpression evaluates only complete, bounded string expressions.
// An unsupported term leaves the path unknown to the write proof.
func literalExpression(language, expression string) (string, bool) {
	return literalExpressionAt(language, strings.TrimSpace(expression), 0)
}

func literalExpressionAt(language, expression string, depth int) (string, bool) {
	if depth >= literalExpressionDepth || len(expression) > maxAnalysisBytes {
		return "", false
	}
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return "", false
	}
	if language == "node" {
		expression = strings.ReplaceAll(expression, `require("path").join(`, "path.join(")
		expression = strings.ReplaceAll(expression, `require('path').join(`, "path.join(")
	}
	if strings.HasPrefix(expression, "(") && literalBalancedOuter(expression) {
		return literalExpressionAt(language, expression[1:len(expression)-1], depth+1)
	}
	for _, op := range []byte{'+'} {
		if parts := literalSplitOperator(expression, op); len(parts) > 1 {
			var result strings.Builder
			for _, part := range parts {
				value, ok := literalExpressionAt(language, part, depth+1)
				if !ok {
					return "", false
				}
				result.WriteString(value)
			}
			return result.String(), true
		}
	}
	if language == "perl" {
		if parts := literalSplitOperator(expression, '.'); len(parts) > 1 {
			var result strings.Builder
			for _, part := range parts {
				value, ok := literalExpressionAt(language, part, depth+1)
				if !ok {
					return "", false
				}
				result.WriteString(value)
			}
			return result.String(), true
		}
	}
	if language == "python" {
		if parts := literalSplitOperator(expression, '%'); len(parts) == 2 {
			format, ok := literalExpressionAt(language, parts[0], depth+1)
			value, valueOK := literalExpressionAt(language, parts[1], depth+1)
			if ok && valueOK && strings.Count(format, "%s") == 1 && !strings.Contains(strings.Replace(format, "%s", "", 1), "%") {
				return strings.Replace(format, "%s", value, 1), true
			}
			return "", false
		}
		if parts := literalSplitOperator(expression, '/'); len(parts) > 1 {
			base, ok := literalExpressionAt(language, parts[0], depth+1)
			if !ok || !strings.HasPrefix(strings.TrimSpace(parts[0]), "Path(") && !strings.HasPrefix(strings.TrimSpace(parts[0]), "pathlib.Path(") {
				return "", false
			}
			for _, part := range parts[1:] {
				component, ok := literalExpressionAt(language, part, depth+1)
				if !ok {
					return "", false
				}
				base = filepath.Join(base, component)
			}
			return base, true
		}
	}
	if (language == "python" || language == "node") && strings.HasSuffix(expression, ")") {
		if index := strings.Index(expression, ".format("); index > 0 && language == "python" {
			format, ok := literalExpressionAt(language, expression[:index], depth+1)
			call := expression[index+len(".format"):]
			if !ok || !literalBalancedOuter(call) {
				return "", false
			}
			for _, arg := range literalCallArgs("format" + call) {
				value, ok := literalExpressionAt(language, arg, depth+1)
				if !ok || !strings.Contains(format, "{}") {
					return "", false
				}
				format = strings.Replace(format, "{}", value, 1)
			}
			if strings.Contains(format, "{") || strings.Contains(format, "}") {
				return "", false
			}
			return format, true
		}
	}
	if language == "python" && len(expression) > 2 && (expression[0] == 'f' || expression[0] == 'F') {
		return literalInterpolatedString(language, expression[1:], depth+1)
	}
	if language == "node" && strings.HasPrefix(expression, "`") {
		return literalInterpolatedString(language, expression, depth+1)
	}
	if value, ok := literalString(expression); ok {
		return value, true
	}
	if language == "python" {
		if value, ok := literalAdjacentStrings(expression); ok {
			return value, true
		}
	}
	if name, args, ok := literalWholeCall(expression); ok {
		switch {
		case language == "python" && (name == "Path" || name == "pathlib.Path") && len(args) == 1:
			return literalExpressionAt(language, args[0], depth+1)
		case language == "python" && name == "os.path.join",
			language == "node" && name == "path.join",
			language == "ruby" && name == "File.join":
			return literalJoinArguments(language, args, depth+1)
		case language == "perl" && name == "join" && len(args) >= 2:
			separator, ok := literalExpressionAt(language, args[0], depth+1)
			if !ok {
				return "", false
			}
			values := make([]string, 0, len(args)-1)
			for _, arg := range args[1:] {
				value, ok := literalExpressionAt(language, arg, depth+1)
				if !ok {
					return "", false
				}
				values = append(values, value)
			}
			return strings.Join(values, separator), true
		case language == "perl" && name == "sprintf" && len(args) == 2:
			format, ok := literalExpressionAt(language, args[0], depth+1)
			value, valueOK := literalExpressionAt(language, args[1], depth+1)
			if ok && valueOK && strings.Count(format, "%s") == 1 && !strings.Contains(strings.Replace(format, "%s", "", 1), "%") {
				return strings.Replace(format, "%s", value, 1), true
			}
		}
	}
	return "", false
}

func literalJoinArguments(language string, args []string, depth int) (string, bool) {
	if len(args) == 0 || len(args) > 32 {
		return "", false
	}
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		value, ok := literalExpressionAt(language, arg, depth+1)
		if !ok {
			return "", false
		}
		parts = append(parts, value)
	}
	return filepath.Join(parts...), true
}

func literalWholeCall(expression string) (string, []string, bool) {
	open := strings.IndexByte(expression, '(')
	if open < 1 || !literalBalancedOuter(expression[open:]) {
		return "", nil, false
	}
	name := strings.TrimSpace(expression[:open])
	if !literalExpressionCallName.MatchString(name) {
		return "", nil, false
	}
	return name, literalCallArgs(expression), true
}

func literalBalancedOuter(value string) bool {
	if len(value) < 2 || value[0] != '(' || value[len(value)-1] != ')' {
		return false
	}
	depth := 0
	var quote byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(value)-1 || depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && quote == 0
}

func literalSplitOperator(value string, operator byte) []string {
	var parts []string
	start, depth := 0, 0
	var quote byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		default:
			if depth == 0 && c == operator {
				parts = append(parts, strings.TrimSpace(value[start:i]))
				start = i + 1
			}
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return append(parts, strings.TrimSpace(value[start:]))
}

func literalAdjacentStrings(value string) (string, bool) {
	var result strings.Builder
	count := 0
	for value = strings.TrimSpace(value); value != ""; value = strings.TrimSpace(value) {
		if value[0] != '\'' && value[0] != '"' {
			return "", false
		}
		end := 1
		for end < len(value) && value[end] != value[0] {
			if value[end] == '\\' {
				return "", false
			}
			end++
		}
		if end >= len(value) {
			return "", false
		}
		result.WriteString(value[1:end])
		count++
		value = value[end+1:]
	}
	return result.String(), count > 1
}

func literalInterpolatedString(language, value string, depth int) (string, bool) {
	if len(value) < 2 {
		return "", false
	}
	quote := value[0]
	if language == "node" && quote != '`' || language == "python" && quote != '\'' && quote != '"' || value[len(value)-1] != quote {
		return "", false
	}
	value = value[1 : len(value)-1]
	var result strings.Builder
	for len(value) > 0 {
		start := strings.IndexByte(value, '{')
		prefix := 0
		if language == "node" {
			start = strings.Index(value, "${")
			prefix = 1
		}
		if start < 0 {
			result.WriteString(value)
			break
		}
		result.WriteString(value[:start])
		end := strings.IndexByte(value[start+prefix+1:], '}')
		if end < 0 {
			return "", false
		}
		end += start + prefix + 1
		part, ok := literalExpressionAt(language, value[start+prefix+1:end], depth+1)
		if !ok {
			return "", false
		}
		result.WriteString(part)
		value = value[end+1:]
	}
	return result.String(), true
}
