// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// processRunsAsCaller reports whether pid's real and effective uid are this
// process's effective uid, from the kernel's /proc/<pid>/status.
func processRunsAsCaller(pid int) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			break
		}
		own := strconv.Itoa(os.Geteuid())
		if fields[0] != own || fields[1] != own {
			return errProcessOfAnotherAccount
		}
		return nil
	}
	return errors.New("no Uid line in the process status")
}
