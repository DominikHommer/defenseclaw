// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Shell fragments for the tests below. $1 is the pid file. The escaped
// child writes its own pid, then runs as sleep with that pid.
const (
	containChild     = `sh -c 'echo $$ > "$0"; exec sleep 60' "$1" </dev/null >/dev/null 2>&1`
	containClosedFDs = `sh -c 'echo $$ > "$0"; exec sleep 60 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-' "$1" </dev/null >/dev/null 2>&1`
	containWaitPID   = `while [ ! -s "$1" ]; do sleep 0.01; done`
	containNewGroup  = `perl -e 'setpgrp(0, 0) or die; exec @ARGV or die' `
)

func requireContainTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"setsid", "perl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
}

// r104 W5b: RunTree kills the command's process group only. A descendant in
// a session or group of its own outlived it, and the Hermes probe passed.
func TestRunContainedEndsDescendantsThatLeaveTheGroup(t *testing.T) {
	requireContainTools(t)
	for _, tc := range []struct {
		name    string
		script  string
		timeout time.Duration
		wantErr bool
	}{
		{"new session", "setsid " + containChild + " &\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"double fork into a new session", "( setsid " + containChild + " & )\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"new session, inherited descriptors closed", "setsid " + containClosedFDs + " &\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"own process group", containNewGroup + containChild + " &\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"session leader that forks again", `setsid sh -c '( sh -c "echo \$\$ > \"\$0\"; exec sleep 60" "$0" & ) ; exit 0' "$1" </dev/null >/dev/null 2>&1 &` + "\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"canceled", "setsid " + containChild + " &\n" + containWaitPID + "\nsleep 60", 500 * time.Millisecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "escaped.pid")
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			cmd := CommandContext(ctx, "/bin/sh", "-c", tc.script, "sh", pidFile)
			cmd.WaitDelay = time.Second
			err := RunContained(cmd)
			pid := readContainPID(t, pidFile)
			if helperRunning(pid) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("RunContained returned (%v) while descendant %d still runs", err, pid)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("RunContained = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// When the supervisor cannot sweep what is left, the run fails closed.
func TestRunContainedFailsClosedWhenItCannotEndTheTree(t *testing.T) {
	requireContainTools(t)
	previous := containSweepBudget
	containSweepBudget = 0
	t.Cleanup(func() { containSweepBudget = previous })
	pidFile := filepath.Join(t.TempDir(), "escaped.pid")
	err := RunContained(CommandContext(context.Background(), "/bin/sh", "-c",
		"setsid "+containChild+" &\n"+containWaitPID+"\nexit 0", "sh", pidFile))
	pid := readContainPID(t, pidFile)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	if !errors.Is(err, ErrNotContained) {
		t.Fatalf("RunContained = %v, want ErrNotContained", err)
	}
}

// A command that kills its supervisor cannot pass.
func TestRunContainedFailsWhenTheSupervisorIsKilled(t *testing.T) {
	requireContainTools(t)
	pidFile := filepath.Join(t.TempDir(), "escaped.pid")
	err := RunContained(CommandContext(context.Background(), "/bin/sh", "-c",
		"setsid "+containChild+" &\n"+containWaitPID+"\n"+
			// Only ever the supervisor: never the test binary.
			`case "$(tr '\0' ' ' < /proc/$PPID/cmdline)" in `+containSupervisorArg0+`*) kill -9 $PPID ;; esac`+
			"\nexit 0", "sh", pidFile))
	pid := readContainPID(t, pidFile)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	if err == nil {
		t.Fatal("RunContained passed after the command killed its supervisor")
	}
}

// The supervisor reports the command's own result and hides its marker.
func TestRunContainedKeepsTheCommandResult(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{"exit 0", 0},
		{"exit 3", 3},
		{"kill -TERM $$", 128 + int(syscall.SIGTERM)},
		{`[ -z "${` + containSupervisorEnv + `+x}" ] || exit 9`, 0},
	} {
		err := RunContained(CommandContext(context.Background(), "/bin/sh", "-c", tc.script))
		got := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			got = exitErr.ExitCode()
		} else if err != nil {
			t.Fatalf("%q: %v", tc.script, err)
		}
		if got != tc.want {
			t.Fatalf("%q exited %d, want %d", tc.script, got, tc.want)
		}
	}
	if err := RunContained(CommandContext(context.Background(), filepath.Join(t.TempDir(), "missing"))); err == nil {
		t.Fatal("a command that cannot start passed")
	}
}

func readContainPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && convErr == nil {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("command never wrote %s: %v", path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
