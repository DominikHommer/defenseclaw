//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package processutil

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// startGroupWatchdog starts a shell that kills process group pgid when this
// process ends, however it ends. It reads a pipe whose only write end this
// process holds (close-on-exec, so no child inherits it); the kernel closes
// that end when this process dies, even by SIGKILL, and the read returns.
// The parent-death signal ends the direct child only (Linux), and macOS has
// none: a helper the scanner started (an MCP server) outlived a killed
// gateway. The returned stop ends the watchdog, which then kills the group
// too.
//
// The watchdog joins group pgid itself. A group lives as long as any member
// does, so its ID cannot be reused while the watchdog runs. When the gateway
// dies after the scanner leader exited, init reaps the orphaned leader, and
// the watchdog's kill still reaches that group only, never one that took
// the ID over. Call it while the leader is unreaped, so the group exists to
// join.
func startGroupWatchdog(pgid int) (stop func(), err error) {
	if pgid <= 1 {
		return nil, fmt.Errorf("processutil: no process group %d to watch", pgid)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	watchdog := exec.Command("/bin/sh", "-c", `read -r _; kill -9 "-$1" 2>/dev/null; exit 0`,
		"defenseclaw-group-watchdog", strconv.Itoa(pgid))
	watchdog.Stdin = r
	watchdog.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: pgid}
	err = watchdog.Start()
	_ = r.Close()
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	return func() { _ = w.Close(); _ = watchdog.Wait() }, nil
}
