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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GAP-0418: a killed gateway left its skill-scanner running; RunTree asks the
// kernel to kill the child with its parent.
func TestRunTreeChildExitsWithItsParent(t *testing.T) {
	cmd := CommandContext(context.Background(), "true")
	if err := RunTree(cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL || !cmd.SysProcAttr.Setpgid {
		t.Fatalf("SysProcAttr = %+v, want Pdeathsig SIGKILL in a process group of its own", cmd.SysProcAttr)
	}
}

// p0 GAP-1156: a process the scanner started (its LLM helper) ends with the
// scanner, when the scanner exits and when its command is canceled.
func TestRunTreeKillsWhatTheChildStarted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		script  string
		timeout time.Duration
	}{
		{"child exits", `sleep 60 & echo $! > "$1"; exit 0`, time.Minute},
		{"command canceled", `sleep 60 & echo $! > "$1"; wait`, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "helper.pid")
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			_ = RunTree(CommandContext(ctx, "/bin/sh", "-c", tc.script, "sh", pidFile))
			raw, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for helperRunning(pid) {
				if time.Now().After(deadline) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("helper %d still runs after its parent ended", pid)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

// helperRunning reports a live, not zombie, process.
func helperRunning(pid int) bool {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
	return len(fields) > 0 && fields[0] != "Z"
}
