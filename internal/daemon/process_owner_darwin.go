// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// processRunsAsCaller reports whether pid's real and effective uid are this
// process's effective uid, from the kernel's kern.proc.pid record.
func processRunsAsCaller(pid int) error {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return err
	}
	if int(info.Proc.P_pid) != pid {
		return errors.New("the kernel has no such process")
	}
	own := uint32(os.Geteuid())
	if info.Eproc.Pcred.P_ruid != own || info.Eproc.Ucred.Uid != own {
		return errProcessOfAnotherAccount
	}
	return nil
}
