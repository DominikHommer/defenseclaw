// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package audit

import "time"

// walCatchUpHoldMaxDefault is zero: Linux and macOS sync a file's dirty pages
// in parallel, so every catch-up keeps walCatchUpCap (walCatchUpHold).
const walCatchUpHoldMaxDefault time.Duration = 0
