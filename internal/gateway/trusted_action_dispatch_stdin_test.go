// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A reader with a file operand does not read the heredoc on its stdin; an
// operand or option value that names stdin, no file operand, an option the
// grammar does not know, or a program outside the table reads it. The file
// words are regular files of the command's directory.
func TestLiteralStdinUnreadReaders(t *testing.T) {
	files := literalStdinFiles{cwd: t.TempDir(), inspect: true}
	for _, name := range []string{"file", "in", "out", "sums"} {
		if err := os.WriteFile(filepath.Join(files.cwd, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
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
		if got := literalStdinUnread(command, files); got != tc.unread {
			t.Errorf("literalStdinUnread(%q) = %t, want %t", tc.command, got, tc.unread)
		}
	}
	wrapped := actionfacts.CommandFact{Program: "grep", Argv: []string{"grep", "acme", "file"},
		ArgvComplete: true, Wrappers: []actionfacts.WrapperFact{{}}}
	if literalStdinUnread(wrapped, files) {
		t.Error("a wrapped reader must count as reading its heredoc")
	}
	partial := actionfacts.CommandFact{Program: "grep", Argv: []string{"grep", "acme", "file"}}
	if literalStdinUnread(partial, files) {
		t.Error("an unresolved argv must count as reading its heredoc")
	}
}

// A file word proves the heredoc unread only when it is the null device or an
// existing regular file the gateway can see in the command's own filesystem:
// any spelling of /dev/stdin, a link (to stdin or not), a linked directory, a
// name that does not exist yet, or a word the gateway cannot look up may be
// stdin when the command reads it.
func TestLiteralStdinUnreadNeedsAFileThatIsNotStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX device and link paths")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"alias": "/dev/stdin", "notes-link": "notes.txt", "devdir": "/dev", "fddir": "/dev/fd"} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fd", "0"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	seen := literalStdinFiles{cwd: dir, inspect: true}
	for _, tc := range []struct {
		command string
		files   literalStdinFiles
		unread  bool
	}{
		{"cat notes.txt", seen, true},
		{"cat " + filepath.Join(dir, "notes.txt"), seen, true},
		{"cat /dev/null", seen, true},
		{"grep -f notes.txt notes.txt", seen, true},
		// Spellings of stdin the old word check missed.
		{"cat /dev/./stdin", seen, false},
		{"cat /dev//stdin", seen, false},
		{"cat //dev/stdin", seen, false},
		{"cat /dev/../dev/stdin", seen, false},
		{"cat /dev/fd/../fd/0", seen, false},
		{"cat devdir/stdin", seen, false},
		{"cat fddir/0", seen, false},
		// Kernel resolution, not a cleaned path: fddir/../fd/0 is
		// /proc/self/fd/0, though <dir>/fd/0 is a regular file.
		{"cat fddir/../fd/0", seen, false},
		{"cat devdir/null", seen, false},
		// Links, and names that may become one.
		{"cat alias", seen, false},
		{"cat notes-link", seen, false},
		{"cat missing.txt", seen, false},
		{"cat devdir", seen, false},
		{"grep -f alias notes.txt", seen, false},
		{"grep --file=alias notes.txt", seen, false},
		{"grep acme notes.txt alias", seen, false},
		{"grep acme notes.txt -e x", seen, false},
		// Without a view of the command's filesystem, or its directory,
		// only the null device is known.
		{"cat notes.txt", literalStdinFiles{cwd: dir}, false},
		{"cat /dev/null", literalStdinFiles{}, true},
		{"cat notes.txt", literalStdinFiles{inspect: true}, false},
		{"cat " + filepath.Join(dir, "notes.txt"), literalStdinFiles{inspect: true}, true},
	} {
		argv := strings.Fields(tc.command)
		command := actionfacts.CommandFact{Program: argv[0], Argv: argv, ArgvComplete: true}
		if got := literalStdinUnread(command, tc.files); got != tc.unread {
			t.Errorf("literalStdinUnread(%q, %+v) = %t, want %t", tc.command, tc.files, got, tc.unread)
		}
	}
}

// The filesystem view holds only when the gateway sees the command's own
// filesystem and nothing in the action can change what a word names first.
func TestLiteralStdinFilesOfTheAction(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		request trustedActionRequest
		command string
		inspect bool
	}{
		{"readers and inert commands", trustedActionRequest{}, "mkdir -p d; cat notes.txt; echo done > out.txt", true},
		{"a link made first", trustedActionRequest{}, "ln -sf /dev/stdin notes.txt; cat notes.txt", false},
		{"a move made first", trustedActionRequest{}, "mv alias notes.txt; cat notes.txt", false},
		{"a directory change", trustedActionRequest{}, "cd /dev; cat stdin", false},
		{"a wrapper", trustedActionRequest{}, "env cat notes.txt", false},
		{"a sandbox", trustedActionRequest{SkipLocalFilesystemResolution: true}, "cat notes.txt", false},
		{"a sandbox guest", trustedActionRequest{SandboxGuestCWD: "/sandbox"}, "cat notes.txt", false},
	} {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: tc.command, CWD: dir})
		files := literalStdinFilesOf(tc.request, facts)
		if files.inspect != tc.inspect || files.cwd != dir {
			t.Errorf("%s: literalStdinFilesOf(%q) = %+v, want inspect=%t cwd=%s", tc.name, tc.command, files, tc.inspect, dir)
		}
	}
}
