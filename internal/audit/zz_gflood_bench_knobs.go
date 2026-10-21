// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// G-flood bench branch only: never merged.
package audit

import (
	"os"
	"strconv"
	"time"
)

func init() {
	if n, err := strconv.Atoi(os.Getenv("GFLOOD_CAP_MS")); err == nil {
		walCatchUpCap = time.Duration(n) * time.Millisecond
	}
	if n, err := strconv.Atoi(os.Getenv("GFLOOD_SETTLE")); err == nil {
		walSettleRounds = n
	}
}
