// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package daemon

import (
	"fmt"
	"runtime"
)

func processEnvironment(int) ([]string, error) {
	return nil, fmt.Errorf("process environments cannot be inspected on %s", runtime.GOOS)
}
