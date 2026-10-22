// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hermespath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0499: on Linux and macOS the account's Hermes home is ~/.hermes only
// while nothing its processes start with sets HERMES_HOME elsewhere. The
// sign-in's environment files, the shell startup files and the environment
// of the account's running processes are read; a value that names another
// home, or that only the shell can evaluate, leaves the home unproven.
func TestVerifyAccountHomeReadsTheAccountsEnvironment(t *testing.T) {
	root := t.TempDir()
	system := filepath.Join(root, "system")
	t.Cleanup(OverrideAccountEnvironmentForTest(system))
	home := filepath.Join(root, "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved := filepath.Join(home, ".hermes")
	work := filepath.Join(home, "work-hermes")
	for _, tc := range []struct {
		name, file, body, want string
	}{
		{"environment.d", filepath.Join(home, ".config", "environment.d", "10-hermes.conf"), "HERMES_HOME=$HOME/work-hermes\n", work},
		{"environment.d braces", filepath.Join(home, ".config", "environment.d", "10-hermes.conf"), "HERMES_HOME=\"${HOME}/work-hermes\"\n", work},
		{"system environment.d", filepath.Join(system, "etc", "environment.d", "50-hermes.conf"), "HERMES_HOME=/srv/hermes\n", "/srv/hermes"},
		{"/etc/environment", filepath.Join(system, "etc", "environment"), "PATH=/usr/bin\nHERMES_HOME=/srv/hermes\n", "/srv/hermes"},
		{"pam_environment", filepath.Join(home, ".pam_environment"), "HERMES_HOME DEFAULT=@{HOME}/work-hermes\n", work},
		{"pam_environment assignment", filepath.Join(home, ".pam_environment"), "HERMES_HOME=" + work + "\n", work},
		{"an unresolvable reference", filepath.Join(home, ".config", "environment.d", "10-hermes.conf"), "HERMES_HOME=${XDG_DATA_HOME}/hermes\n", "cannot resolve"},
		{"a shell startup file", filepath.Join(home, ".bashrc"), "# HERMES_HOME is set below\nexport HERMES_HOME=~/work-hermes\n", "cannot resolve"},
		{"a system profile script", filepath.Join(system, "etc", "profile.d", "hermes.sh"), "export HERMES_HOME=/srv/hermes\n", "cannot resolve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.MkdirAll(filepath.Dir(tc.file), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tc.file, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(tc.file) })
			err := VerifyAccountHome(home, resolved)
			if err == nil || !strings.Contains(err.Error(), "HERMES_HOME unproven") || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.file) {
				t.Fatalf("VerifyAccountHome = %v, want unproven naming %s and %q", err, tc.file, tc.want)
			}
		})
	}
	for name, body := range map[string]string{
		"the resolved home":      "HERMES_HOME=$HOME/.hermes\n",
		"a comment":              "# HERMES_HOME=/srv/hermes\n",
		"another variable":       "PATH=/usr/bin\nHERMES_HOME_BACKUP=/srv/old\n",
		"a commented shell line": "# export HERMES_HOME=/srv/hermes\n",
	} {
		file := filepath.Join(home, ".config", "environment.d", "10-hermes.conf")
		if strings.Contains(name, "shell") {
			file = filepath.Join(home, ".bashrc")
		}
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyAccountHome(home, resolved); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		_ = os.Remove(file)
	}
}

// A running process of the account that started with another HERMES_HOME
// (a shell rc export the sign-in files do not show) leaves the home
// unproven, and one of another account does not.
func TestVerifyAccountHomeReadsTheAccountsRunningProcesses(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("running process environments are read from /proc on Linux")
	}
	root := t.TempDir()
	system := filepath.Join(root, "system")
	t.Cleanup(OverrideAccountEnvironmentForTest(system))
	home := filepath.Join(root, "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	process := filepath.Join(system, "proc", "4242")
	if err := os.MkdirAll(process, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(process, "comm"), []byte("hermes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(process, "environ"), []byte("PATH=/usr/bin\x00HERMES_HOME=/srv/hermes\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := VerifyAccountHome(home, filepath.Join(home, ".hermes"))
	if err == nil || !strings.Contains(err.Error(), "running process 4242 (hermes)") || !strings.Contains(err.Error(), "/srv/hermes") {
		t.Fatalf("VerifyAccountHome = %v, want unproven naming the process", err)
	}
	if err := os.WriteFile(filepath.Join(process, "environ"), []byte("PATH=/usr/bin\x00HERMES_HOME="+filepath.Join(home, ".hermes")+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAccountHome(home, filepath.Join(home, ".hermes")); err != nil {
		t.Fatalf("a process with the resolved home: %v", err)
	}
}
