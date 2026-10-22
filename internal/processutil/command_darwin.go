//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package processutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func configureCapturedCommand(_ *exec.Cmd) {}

func combinedOutputTree(cmd *exec.Cmd, _ bool) ([]byte, error) {
	if cmd.Stdout != nil || cmd.Stderr != nil {
		return nil, errors.New("processutil: CombinedOutputTree requires unset stdout and stderr")
	}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := runTree(cmd, false)
	return output.Bytes(), err
}

// macOS has no Linux parent-death signal. Start the command as a process
// group leader behind a one-byte start gate. Its gateway-arms watchdog must
// be running before that gate opens: even a SIGKILL in the narrow interval
// after Start cannot leave a scanner executing without a supervisor.
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
	cmd.Cancel = func() error { return killDarwinGroup(cmd.Process.Pid) }
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = 5 * time.Second
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = startRead.Close()
	pid := cmd.Process.Pid
	stopWatchdog, err := startDarwinWatchdog(pid)
	if err != nil {
		_ = killDarwinGroup(pid)
		_ = cmd.Wait()
		return err
	}
	defer stopWatchdog()
	kq, err := unix.Kqueue()
	if err != nil {
		_ = killDarwinGroup(pid)
		_ = cmd.Wait()
		return err
	}
	defer unix.Close(kq)
	change := []unix.Kevent_t{{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}}
	if _, err := unix.Kevent(kq, change, nil, nil); err != nil {
		_ = killDarwinGroup(pid)
		_ = cmd.Wait()
		return err
	}
	if _, err := startWrite.Write([]byte("go\n")); err != nil {
		_ = killDarwinGroup(pid)
		_ = cmd.Wait()
		return fmt.Errorf("processutil: release scanner start gate: %w", err)
	}
	_ = startWrite.Close()
	var event [1]unix.Kevent_t
	for {
		if _, err := unix.Kevent(kq, nil, event[:], nil); errors.Is(err, unix.EINTR) {
			continue
		} else if err != nil {
			_ = killDarwinGroup(pid)
			_ = cmd.Wait()
			return err
		}
		break
	}
	// NOTE_EXIT arrives while the direct child is still a zombie. Kill its
	// descendants before Wait reaps the leader and permits PID reuse.
	_ = killDarwinGroup(pid)
	return cmd.Wait()
}

func startDarwinWatchdog(pgid int) (func(), error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	watchdog := exec.Command("/bin/sh", "-c", `read -r _; kill -9 "-$1" 2>/dev/null; exit 0`,
		"defenseclaw-group-watchdog", strconv.Itoa(pgid))
	watchdog.Stdin = r
	watchdog.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = watchdog.Start()
	_ = r.Close()
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	return func() { _ = w.Close(); _ = watchdog.Wait() }, nil
}

func killDarwinGroup(pid int) error {
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
