//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package processutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func configureCapturedCommand(_ *exec.Cmd) {}

func combinedOutputTree(cmd *exec.Cmd, _ bool) ([]byte, error) { return cmd.CombinedOutput() }

// darwinTreeWaitDelay bounds the wait for a command's output streams once its
// process group has ended. A process that left the group can hold a stream
// open; Wait then returns exec.ErrWaitDelay, never a clean exit.
const darwinTreeWaitDelay = 5 * time.Second

// Test seams.
var (
	startDarwinWatchdog    = startGroupWatchdog
	releaseDarwinStartGate = func(w *os.File) error { _, err := w.Write([]byte("go\n")); return err }
	signalDarwinGroup      = func(pgid int) error { return syscall.Kill(-pgid, syscall.SIGKILL) }
	afterDarwinLeaderExit  = func() {}
)

// macOS has no Linux parent-death signal. Start the command as a process
// group leader behind a one-byte start gate. Its gateway-arms watchdog must
// be running before that gate opens: even a SIGKILL in the narrow interval
// after Start cannot leave a scanner executing without a supervisor.
//
// This process signals the group only while the leader is still unreaped:
// its PID, and with it the group ID, cannot be reused until Wait reaps it.
// The watchdog is itself a member of the group, so the group ID stays its
// own also when the gateway died and launchd reaped the leader before the
// watchdog's kill.
func runTree(cmd *exec.Cmd, _ bool) error {
	if cmd == nil {
		return errors.New("processutil: nil command")
	}
	startRead, startWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer startWrite.Close()
	defer startRead.Close()
	startFD := 3 + len(cmd.ExtraFiles)
	cmd.ExtraFiles = append(cmd.ExtraFiles, startRead)
	path, args := cmd.Path, append([]string(nil), cmd.Args[1:]...)
	if path == "" {
		return errors.New("processutil: empty command path")
	}
	// Only the descriptor number is interpolated into this fixed script;
	// the executable and arguments remain separate positional parameters.
	fd := strconv.Itoa(startFD)
	cmd.Path = "/bin/sh"
	cmd.Args = append([]string{"sh", "-c", "IFS= read -r ready <&" + fd + " || exit 1; exec " + fd + "<&-; exec \"$@\"", "defenseclaw-scanner-supervisor", path}, args...)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	// reaping is set, under signalMu, before Wait may reap the leader. A
	// cancellation that comes later finds the group already ended and
	// signals nothing.
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
			return killDarwinGroup(cmd.Process.Pid)
		}
	}
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = darwinTreeWaitDelay
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = startRead.Close()
	pid := cmd.Process.Pid
	stopWatchdog := func() {}
	// finish ends the group, then the watchdog (whose last act is one more
	// kill of the group), and only then lets Wait reap the leader.
	finish := func(cause error) error {
		signalMu.Lock()
		reaping = true
		signalMu.Unlock()
		_ = killDarwinGroup(pid)
		stopWatchdog()
		waitErr := cmd.Wait()
		if cause != nil {
			return cause
		}
		return waitErr
	}
	stop, err := startDarwinWatchdog(pid)
	if err != nil {
		return finish(err)
	}
	stopWatchdog = stop
	kq, err := unix.Kqueue()
	if err != nil {
		return finish(err)
	}
	defer unix.Close(kq)
	change := []unix.Kevent_t{{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}}
	if _, err := unix.Kevent(kq, change, nil, nil); err != nil {
		return finish(err)
	}
	if err := releaseDarwinStartGate(startWrite); err != nil {
		return finish(fmt.Errorf("processutil: release scanner start gate: %w", err))
	}
	_ = startWrite.Close()
	var event [1]unix.Kevent_t
	for {
		_, err := unix.Kevent(kq, nil, event[:], nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return finish(err)
		}
		break
	}
	// NOTE_EXIT arrives while the direct child is still a zombie.
	afterDarwinLeaderExit()
	return finish(nil)
}

func killDarwinGroup(pid int) error {
	err := signalDarwinGroup(pid)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
