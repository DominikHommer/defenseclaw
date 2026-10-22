// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"fmt"
	"io"
	"os"
)

// processEnvironment is the environment the kernel recorded when pid
// executed its program (/proc/<pid>/environ, readable only by the process's
// own account and root).
func processEnvironment(pid int) ([]string, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxProcessEnvironmentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProcessEnvironmentBytes {
		return nil, fmt.Errorf("the environment of PID %d exceeds %d bytes", pid, maxProcessEnvironmentBytes)
	}
	return splitNULStrings(data), nil
}
