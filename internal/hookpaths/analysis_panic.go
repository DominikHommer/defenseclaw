// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "sync/atomic"

// analysisPanicCount records unexpected analysis failures without retaining
// command text. Entry points return incomplete results after recovery.
var analysisPanicCount atomic.Uint64

func recoverAnalysisPanic(incomplete func()) {
	if recover() != nil {
		analysisPanicCount.Add(1)
		incomplete()
	}
}
