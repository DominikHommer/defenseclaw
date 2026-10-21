//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"os/exec"
	"runtime"
	"syscall"
)

// trustedCommandSysProcAttr puts a directory tool in its own process group
// and has the kernel kill it when the process that started it ends. The
// timeout of runTrustedCommand is the parent's: a managed hook ends with
// os.Exit as soon as its answer is out, and a getent its failure-row lookup
// started was then left running for as long as NSS stalled (an SSSD, LDAP or
// winbind outage), one more for each hook call (G-small loop 4).
func trustedCommandSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// runBoundToParent runs cmd on a thread locked to this goroutine for the
// whole run. Linux sends the parent-death signal when the thread that
// started the child ends, not the process; locked, that thread cannot be
// handed to a goroutine that ends it while the tool still runs.
func runBoundToParent(cmd *exec.Cmd) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return cmd.Run()
}
