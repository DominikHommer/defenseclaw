// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package audit

import "time"

// walCatchUpHoldMaxDefault bounds a Windows catch-up's hold of the writer
// (walCatchUpHold). It stays under a second so a hook that waits behind a
// catch-up still answers well inside every hook timeout, and the metric
// writes that give up after a second still land.
const walCatchUpHoldMaxDefault = 800 * time.Millisecond
