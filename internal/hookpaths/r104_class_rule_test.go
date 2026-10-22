// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestR104ActionClassUnknownShellAndInterpreter(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"writer.sh": "echo marker >> \"$2\"\n",
		"safe.sh":   "echo marker >> report.txt\n",
	} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "outside.sh"), []byte("echo marker >> report.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"unknown shell option", `bash --rcfile config -c 'echo marker >> report.txt'`, true},
		{"shell stdin", `bash -s`, true},
		{"shell redirected stdin", `bash < safe.sh`, true},
		{"shell heredoc", "sh <<'EOF'\necho marker >> report.txt\nEOF", true},
		{"outside script", `bash ../outside.sh`, true},
		{"script with arguments", `bash safe.sh one two`, true},
		{"positional parameter 2", `bash -c 'echo marker >> "$2"' sh report.txt alias`, true},
		{"positional parameter 9", `sh -c 'echo marker >> "$9"' sh a b c d e f g h alias`, true},
		{"computed program", `$(printf ln) -s report.txt alias`, true},
		{"computed target", `echo marker >> "$(cat target-name.txt)"`, true},
		{"unknown variable target", `echo marker >> "$destination"`, true},
		{"unknown input to write-capable program", `tee report.txt < "$source"`, true},
		{"unknown input to read-only program", `cat < "$source"`, false},
		{"unknown program", `"$writer" report.txt`, true},
		{"eval", `eval 'echo marker >> report.txt'`, true},
		{"ordinary inline shell", `bash -c 'echo marker >> report.txt'`, false},
		{"ordinary local script", `bash safe.sh`, false},
		{"ordinary redirect", `echo marker >> report.txt`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, cwd, home) != ""; got != tc.block {
				t.Fatalf("unknown write = %t, want %t", got, tc.block)
			}
		})
	}
}

func TestR104ActionClassBoundedOrdinaryValues(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"report.txt": "report.txt\n", "target-name.txt": "alias\n"} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`v=build/item.txt; echo ok >> "$v"`, false},
		{`export OUTPUT_DIR=out; printf ready > "$OUTPUT_DIR/status.txt"`, false},
		{`printf -v f 'out/%s' report.txt; echo ok >> "$f"`, false},
		{`out=$(printf out); echo ok > "$out/result.txt"`, false},
		{`read f < report.txt; echo ok > "out/$f"`, false},
		{`echo ok > "out/run-$RANDOM.log"`, false},
		{`read f < target-name.txt; echo ok > "$f"`, true},
		{`v=alias; if false; then v=report.txt; fi; echo ok > "$v"`, true},
		{`if test "$COND"; then v=report.txt; fi; echo ok > "$v"`, true},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if reason := ActionCommandDecision(tc.command, cwd, home); (reason != "") != tc.block {
				t.Fatalf("reason=%q, want block=%t", reason, tc.block)
			}
		})
	}
}

func TestR104ActionClassWrapperRecursion(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	body := `sh -c 'echo marker >> "$destination"'`
	for _, tc := range []struct{ name, command string }{
		{"env split", `env -S "sh -c 'echo marker >> \"$destination\"'"`},
		{"nice", "nice -n 5 " + body},
		{"ionice", "ionice -c 2 " + body},
		{"timeout", "timeout 30 " + body},
		{"stdbuf", "stdbuf -oL " + body},
		{"setsid", "setsid -w " + body},
		{"chroot", "chroot / " + body},
		{"unshare", "unshare -m " + body},
		{"nsenter", "nsenter -t 123 " + body},
		{"flock", "flock -n /tmp/lock " + body},
		{"flock protected lock", `flock -n alias sh -c 'echo marker > report.txt'`},
		{"sudo", "sudo -n " + body},
		{"su", `su -c 'echo marker >> "$destination"' user`},
		{"script", `script -q -c 'echo marker >> "$destination"' transcript`},
		{"script protected transcript", `script -q -c 'echo marker > report.txt' alias`},
		{"xargs", `printf payload | xargs sh -c 'echo marker >> "$destination"'`},
		{"find", `find . -exec sh -c 'echo marker >> "$destination"' sh {} \;`},
		{"parallel", `parallel sh -c 'echo marker >> "$destination"' ::: one`},
		{"git inline alias", `git -c 'alias.writer=!sh -c "echo marker >> alias"' writer`},
		{"git ssh command", `git -c 'core.sshCommand=sh -c "echo marker >> alias"' fetch origin`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := ActionCommandDecision(tc.command, cwd, home); reason == "" {
				t.Fatal("write-capable wrapper hid an unresolved child target")
			}
		})
	}
}

// Each lead gap is kept as a named row so a later parser change cannot
// silently reopen one variant while the broader class tests stay green.
func TestR104LeadGapCorpusPOSIX(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ gap, command string }{
		{"GAP-0539 here-string tee", `tee -a alias <<< marker`},
		{"GAP-0553 xargs child", `printf alias | xargs -I {} sh -c 'echo marker >> "{}"'`},
		{"GAP-0560 env split string", `env -S "sh -c 'echo marker >> alias'"`},
		{"GAP-0659 computed program", `$(printf ln) -s report.txt alias`},
	} {
		t.Run(row.gap, func(t *testing.T) {
			if reason := ActionCommandDecision(row.command, cwd, home); reason == "" {
				t.Fatalf("allowed %q", row.command)
			}
		})
	}
}
