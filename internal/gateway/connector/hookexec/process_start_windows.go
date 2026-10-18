// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"time"

	"golang.org/x/sys/windows"
)

// processStartTimeKnown reports a system that names the process start.
const processStartTimeKnown = true

func processStartTime(time.Time) (time.Time, bool) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, creation.Nanoseconds()), true
}
