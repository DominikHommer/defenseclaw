// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A reader with a file operand does not read the heredoc on its stdin; an
// operand or option value that names stdin, no file operand, an option the
// grammar does not know, or a program outside the table reads it.
func TestLiteralStdinUnreadReaders(t *testing.T) {
	for _, tc := range []struct {
		command string
		unread  bool
	}{
		{"cat /dev/null", true},
		{"cat -n file", true},
		{"cat", false},
		{"cat -", false},
		{"cat file -", false},
		{"cat /dev/stdin", false},
		{"cat /dev/fd/0", false},
		{"cat /proc/self/fd/0", false},
		{"grep acme /dev/null", true},
		{"grep -n acme file", true},
		{"grep -in acme file", true},
		{"grep -e acme file", true},
		{"grep -eacme file", true},
		{"grep --regexp=acme file", true},
		{"grep --regexp acme file", true},
		{"grep --ignore-case acme file", true},
		{"grep -A 3 acme file", true},
		{"grep -A3 acme file", true},
		{"egrep acme file", true},
		{"fgrep -- -x file", true},
		{"grep acme", false},
		{"grep -e acme", false},
		{"grep -A 3 acme", false},
		{"grep -n acme", false},
		{"grep -f - file", false},
		{"grep -f- file", false},
		{"grep --file=- file", false},
		{"grep --file - file", false},
		{"grep acme -", false},
		{"grep -r acme", false},
		{"grep -5 acme file", false},
		{"grep --unknown acme file", false},
		{"grep -X acme file", false},
		{"head -n 1 file", true},
		{"head -n1 file", true},
		{"head -n 1", false},
		{"head file", true},
		{"tail -f file", true},
		{"tail -n 5", false},
		{"wc -l file", true},
		{"wc -l", false},
		{"wc --files0-from=-", false},
		{"sort -o out", false},
		{"sort -o out file", true},
		{"sort -k 2 -t , file", true},
		{"uniq -c in out", true},
		{"uniq -f 1", false},
		{"cut -d , -f 1 file", true},
		{"cut -d , -f 1", false},
		{"sha256sum file", true},
		{"sha256sum", false},
		// A checksum list may name "-".
		{"sha256sum -c sums", false},
		{"sha256sum --check sums", false},
		// Only a file word names stdin: a pattern or another option value of
		// "-" (or a path) is data.
		{"grep -e - /dev/null", true},
		{"grep -e- file", true},
		{"grep --regexp=- file", true},
		{"grep --regexp - file", true},
		{"grep - file", true},
		{"grep -- - file", true},
		{"grep -e /dev/stdin file", true},
		{"grep /proc/ file", true},
		{"grep --label=- acme file", true},
		{"grep --color=auto acme file", true},
		{"cut -d - -f 1 file", true},
		{"cut -d- -f1 file", true},
		{"sort -t - -k 2 file", true},
		{"tac -s - file", true},
		{"head -n -1 file", true},
		{"grep -e - -", false},
		{"grep -e acme -f - file", false},
		{"grep - -e acme file", false},
		{"grep -- - -", false},
		// With POSIXLY_CORRECT, options end at the first operand.
		{"grep acme file -e -", false},
		{"grep acme file -f /dev/stdin", false},
		// An option without its value.
		{"grep -e", false},
		{"grep acme file -A", false},
		{"grep --regexp", false},
		{"grep --file= file", true},
		{"sed -n p file", false},
		{"awk 1 file", false},
		{"tee file", false},
		{"true", true},
	} {
		argv := strings.Fields(tc.command)
		command := actionfacts.CommandFact{Program: argv[0], Argv: argv, ArgvComplete: true}
		if got := literalStdinUnread(command); got != tc.unread {
			t.Errorf("literalStdinUnread(%q) = %t, want %t", tc.command, got, tc.unread)
		}
	}
	wrapped := actionfacts.CommandFact{Program: "grep", Argv: []string{"grep", "acme", "file"},
		ArgvComplete: true, Wrappers: []actionfacts.WrapperFact{{}}}
	if literalStdinUnread(wrapped) {
		t.Error("a wrapped reader must count as reading its heredoc")
	}
	partial := actionfacts.CommandFact{Program: "grep", Argv: []string{"grep", "acme", "file"}}
	if literalStdinUnread(partial) {
		t.Error("an unresolved argv must count as reading its heredoc")
	}
}
