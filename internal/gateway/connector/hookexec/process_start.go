// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "time"

// hookProcessInit is when this package was initialized, the fallback for
// ProcessStartTime.
var hookProcessInit = time.Now()

// maxProcessStartAge bounds the age ProcessStartTime accepts from the
// operating system; anything older (or in the future) is a clock problem,
// and the package's own start is used instead.
const maxProcessStartAge = 30 * time.Second

// ProcessStartTime is when the operating system created this process, so a
// hook's time budgets count the launch and the runtime resolution that come
// before Run (they took seconds on a busy Windows host during an
// attestation repair, GAP-0155). It falls back to the package's
// initialization time where the system does not say.
func ProcessStartTime() time.Time {
	now := time.Now()
	if started, ok := processStartTime(now); ok {
		if age := now.Sub(started); age >= 0 && age <= maxProcessStartAge {
			return started
		}
	}
	return hookProcessInit
}
