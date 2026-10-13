// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// shellPrintfValue evaluates the literal string forms used by shell printf.
// Other conversions remain unknown until their output can be determined.
func shellPrintfValue(format string, args []string) (string, bool) {
	var result strings.Builder
	for {
		used := 0
		conversions := 0
		for i := 0; i < len(format); i++ {
			switch format[i] {
			case '\\':
				if i+1 >= len(format) {
					return "", false
				}
				i++
				switch format[i] {
				case '\\':
					result.WriteByte('\\')
				case 'n':
					result.WriteByte('\n')
				case 't':
					result.WriteByte('\t')
				default:
					return "", false
				}
			case '%':
				i++
				if i >= len(format) {
					return "", false
				}
				switch format[i] {
				case '%':
					result.WriteByte('%')
				case 's':
					conversions++
					if used < len(args) {
						result.WriteString(args[used])
						used++
					}
				default:
					return "", false
				}
			default:
				result.WriteByte(format[i])
			}
		}
		if used >= len(args) || conversions == 0 {
			break
		}
		args = args[used:]
	}
	value := result.String()
	return value, !strings.ContainsAny(value, "\x00\r\n")
}
