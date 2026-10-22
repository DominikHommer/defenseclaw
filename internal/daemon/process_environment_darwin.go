// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import "golang.org/x/sys/unix"

// processEnvironment is the environment kern.procargs2 records for pid, which
// the kernel gives only to the process's own account and root.
func processEnvironment(pid int) ([]string, error) {
	data, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, err
	}
	return procArgs2Environment(data)
}
