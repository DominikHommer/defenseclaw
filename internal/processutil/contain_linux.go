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
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// On Linux, RunContained runs cmd below a child subreaper custodian and a
// separate runner. A command that kills its immediate parent kills the runner;
// its descendants are then reparented to the custodian, which kills and reaps
// them. The custodian is a separate process so gateway children are never
// included in its sweep.
const (
	containSupervisorArg0 = "defenseclaw-contained-run"
	containSupervisorEnv  = "DEFENSECLAW_CONTAINED_RUN_SUPERVISOR"
	containCustodianMode  = "custodian"
	containRunnerMode     = "runner"
)

// Supervisor exit codes. Any other code is the command's own (128+signal
// for a command killed by a signal).
const (
	// containExitTerminated: the supervisor was told to end (cancellation
	// or the death of its parent) and ended everything.
	containExitTerminated = 124
	// containExitNotContained: the supervisor could not prove that nothing
	// the command started still runs.
	containExitNotContained = 125
	// containExitNotStarted: the command could not start.
	containExitNotStarted = 127
)

// containSweepBudget bounds the supervisor's sweep of what the command left;
// tests set it to zero to reach the fail-closed result.
var containSweepBudget = 2 * time.Second

func init() {
	if len(os.Args) < 5 || os.Args[0] != containSupervisorArg0 || os.Args[3] != "--" ||
		os.Getenv(containSupervisorEnv) != "1" {
		return
	}
	budget, err := time.ParseDuration(os.Args[2])
	if err != nil || budget < 0 {
		os.Exit(containExitNotContained)
	}
	switch os.Args[1] {
	case containCustodianMode:
		os.Exit(superviseContained(os.Args[4:], budget))
	case containRunnerMode:
		os.Exit(runContainedCommand(os.Args[4:]))
	default:
		os.Exit(containExitNotContained)
	}
}

func runContained(cmd *exec.Cmd) error {
	if cmd.Process != nil {
		return errors.New("processutil: RunContained: already started")
	}
	target := cmd.Path
	cmd.Path = "/proc/self/exe"
	cmd.Args = append([]string{containSupervisorArg0, containCustodianMode, containSweepBudget.String(), "--", target}, cmd.Args[1:]...)
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(withoutEnv(env, containSupervisorEnv), containSupervisorEnv+"=1")
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	// The supervisor ends and reaps the tree when this thread dies or the
	// command is canceled. Killing the supervisor instead would hand what
	// left the command's group to init.
	cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
	if cmd.Cancel != nil {
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	}
	// The parent-death signal follows the thread that started the child.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == containExitNotContained {
		return fmt.Errorf("%w: %s", ErrNotContained, target)
	}
	return err
}

// superviseContained owns the tree after the runner exits, including when a
// hook sends SIGKILL to the runner. Its own wait and sweep are confined to this
// process, never to the gateway that launched it.
func superviseContained(argv []string, budget time.Duration) int {
	runtime.LockOSThread()
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM)
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return containExitNotContained
	}
	if os.Getppid() == 1 {
		// The parent died before the parent-death signal was armed.
		return containExitTerminated
	}
	child := exec.Command("/proc/self/exe", argv...)
	child.Args = append([]string{containSupervisorArg0, containRunnerMode, budget.String(), "--"}, argv...)
	child.Env = os.Environ()
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := child.Start(); err != nil {
		return containExitNotStarted
	}
	// Only the command and what it started hold its streams now, so the
	// parent's pipe closes when they are gone.
	releaseStdio()
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	terminated := false
	var waitErr error
	select {
	case waitErr = <-done:
	case <-terms:
		terminated = true
		_ = unix.Kill(-child.Process.Pid, unix.SIGKILL)
		_ = child.Process.Kill()
		waitErr = <-done
	}
	if !reapAllChildren(budget) {
		return containExitNotContained
	}
	select {
	case <-terms:
		terminated = true
	default:
	}
	if terminated {
		return containExitTerminated
	}
	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		return 0
	case errors.As(waitErr, &exitErr):
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return containExitNotContained
		}
		return exitErr.ExitCode()
	default:
		return containExitNotContained
	}
}

// runContainedCommand is the hook's immediate parent. It is deliberately not
// a subreaper: if the hook kills it, every orphan moves to the custodian.
func runContainedCommand(argv []string) int {
	runtime.LockOSThread()
	if os.Getppid() == 1 {
		return containExitNotContained
	}
	child := exec.Command(argv[0], argv[1:]...)
	child.Env = withoutEnv(os.Environ(), containSupervisorEnv)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := child.Start(); err != nil {
		return containExitNotStarted
	}
	releaseStdio()
	err := child.Wait()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr):
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exitErr.ExitCode()
	default:
		return containExitNotContained
	}
}

// reapAllChildren kills and reaps this process's children until it has
// none. As a subreaper, this process becomes the parent of every orphaned
// descendant, so no child left means no descendant left. It reports false
// when children remain after budget.
func reapAllChildren(budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	self := os.Getpid()
	for {
		for {
			var status unix.WaitStatus
			pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
			if errors.Is(err, unix.ECHILD) {
				return true
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return false
			}
			if pid <= 0 {
				break
			}
		}
		if !time.Now().Before(deadline) {
			return false
		}
		for _, pid := range childPIDs(self) {
			_ = unix.Kill(pid, unix.SIGKILL)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// childPIDs lists the processes whose parent is parent.
func childPIDs(parent int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	want := strconv.Itoa(parent)
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		stat := string(raw)
		fields := strings.Fields(stat[strings.LastIndexByte(stat, ')')+1:])
		if len(fields) > 1 && fields[1] == want {
			pids = append(pids, pid)
		}
	}
	return pids
}

// releaseStdio points the supervisor's standard streams at /dev/null.
func releaseStdio() {
	null, err := unix.Open(os.DevNull, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	for fd := 0; fd <= 2; fd++ {
		_ = unix.Dup3(null, fd, 0)
	}
	_ = unix.Close(null)
}

// runTracked is runContained: the custodian is a child subreaper, so the
// kernel hands it every orphan of the tree.
func runTracked(cmd *exec.Cmd) error {
	return runContained(cmd)
}
