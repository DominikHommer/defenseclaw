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
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Test seams.
var (
	signalLinuxGroup     = func(pgid int) error { return syscall.Kill(-pgid, syscall.SIGKILL) }
	afterLinuxLeaderExit = func() {}
)

// exitWithParent asks the kernel to kill the child with its parent
// (GAP-0418) and starts it in a process group of its own, so the child and
// whatever it starts end together: a canceled command kills the group, and
// killDescendantsAtExit kills what is left of it when the child exits. The
// parent-death signal reaches the direct child only, and an LLM helper a
// scanner started outlived the gateway (p0 GAP-1156).
//
// Call the returned beginReap before Wait may reap the child. exec's
// context watcher can call Cancel after Wait reaped it, when the child's
// PID, and so its group ID, may already name an unrelated group; from
// beginReap on, Cancel signals nothing and returns os.ErrProcessDone.
func exitWithParent(cmd *exec.Cmd) (beginReap func()) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	cmd.SysProcAttr.Setpgid = true
	var signalMu sync.Mutex
	reaping := false
	// exec.CommandContext sets Cancel; exec.Command leaves it nil, and Start
	// refuses a Cancel without a context.
	if cmd.Cancel != nil {
		cmd.Cancel = func() error {
			signalMu.Lock()
			defer signalMu.Unlock()
			if reaping {
				return os.ErrProcessDone
			}
			return killGroup(cmd.Process.Pid)
		}
	}
	return func() {
		signalMu.Lock()
		reaping = true
		signalMu.Unlock()
	}
}

// killDescendantsAtExit waits, without reaping it, for the child to exit and
// kills the rest of its process group. The child is not reaped yet, so its
// pid, which is the group id, cannot have been reused. Until then a
// watchdog (startGroupWatchdog), itself a member of the group, kills the
// group if this process dies first. Without a pipe or a shell nothing is
// watched; the parent-death signal still ends the child.
func killDescendantsAtExit(cmd *exec.Cmd) {
	if cmd.Process == nil || cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		return
	}
	if stop, err := startGroupWatchdog(cmd.Process.Pid); err == nil {
		defer stop()
	}
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return
		}
		break
	}
	afterLinuxLeaderExit()
	_ = killGroup(cmd.Process.Pid)
}

func killGroup(pid int) error {
	err := signalLinuxGroup(pid)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
