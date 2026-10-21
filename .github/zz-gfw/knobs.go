// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// G-flood-wal bench branch only: never merged.
package audit

import (
	"fmt"
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
	ms("GFLOOD_BCAP_MS", &walBoundedCatchUpCap)
	if n, err := strconv.Atoi(os.Getenv("GFLOOD_SETTLE")); err == nil {
		walSettleRounds = n
	}
}

var gfwTraceOn = os.Getenv("GFW_TRACE") == "1"

func gfwTrace(format string, args ...any) {
	if gfwTraceOn {
		fmt.Fprintf(os.Stderr, "gfw %s "+format+"\n", append([]any{time.Now().Format("15:04:05.000")}, args...)...)
	}
}
