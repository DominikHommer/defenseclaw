// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package daemon

import (
	"fmt"
	"runtime"
)

func processRunsAsCaller(int) error {
	return fmt.Errorf("process owners cannot be inspected on %s", runtime.GOOS)
}
