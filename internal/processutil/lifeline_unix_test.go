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

//go:build linux || darwin

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

// macOS (no subreaper): the lifeline turns a descendant that left the
// process group into a failed run instead of a silent pass (r104 W5b).
func TestRunTreeWithLifelineFailsClosedForADescendantOutsideTheGroup(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not installed")
	}
	const child = `sh -c 'echo $$ > "$0"; exec sleep 60' "$1" </dev/null >/dev/null 2>&1`
	const waitPID = `while [ ! -s "$1" ]; do sleep 0.01; done`
	previous := lifelineWait
	lifelineWait = 300 * time.Millisecond
	t.Cleanup(func() { lifelineWait = previous })
	for _, tc := range []struct {
		name    string
		script  string
		escaped bool
	}{
		{"child in the group", child + " &\n" + waitPID + "\nexit 0", false},
		{"child in a new session", `perl -MPOSIX -e 'POSIX::setsid() >= 0 or die; exec @ARGV or die' ` + child + " &\n" + waitPID + "\nexit 0", true},
		{"child in its own group", `perl -e 'setpgrp(0, 0) or die; exec @ARGV or die' ` + child + " &\n" + waitPID + "\nexit 0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			err := runTreeWithLifeline(CommandContext(context.Background(), "/bin/sh", "-c", tc.script, "sh", pidFile))
			pid := readLifelinePID(t, pidFile)
			if tc.escaped {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				if !errors.Is(err, ErrNotContained) {
					t.Fatalf("run = %v with descendant %d outside the group; want ErrNotContained", err, pid)
				}
				return
			}
			running := lifelineHolderRunning(pid)
			_ = syscall.Kill(pid, syscall.SIGKILL)
			if err != nil || running {
				t.Fatalf("run = %v, descendant running %v; want nil and the group killed", err, running)
			}
		})
	}
}

func readLifelinePID(t *testing.T, path string) int {
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

// lifelineHolderRunning reports a live process; a zombie is not.
func lifelineHolderRunning(pid int) bool {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return false
		}
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if err == nil {
			fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
			if len(fields) > 0 && fields[0] == "Z" {
				return false
			}
		}
		if time.Now().After(deadline) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
}
