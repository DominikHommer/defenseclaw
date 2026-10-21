// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// G-flood-wal bench branch only: never merged.
package audit

import (
	"os"
	"strconv"
	"time"
)

func init() {
	ms := func(name string, target *time.Duration) {
		if n, err := strconv.Atoi(os.Getenv(name)); err == nil {
			*target = time.Duration(n) * time.Millisecond
		}
	}
	ms("GFLOOD_CAP_MS", &walCatchUpCap)
	ms("GFLOOD_SETTLED_MS", &walSettledSync)
	ms("GFLOOD_IDLE_MS", &walIdleWindow)
	ms("GFLOOD_IDLEWAIT_MS", &walIdleWait)
	if n, err := strconv.Atoi(os.Getenv("GFLOOD_SETTLE")); err == nil {
		walSettleRounds = n
	}
}
