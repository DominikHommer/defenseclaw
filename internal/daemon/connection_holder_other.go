// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package daemon

import "net/netip"

func findConnectionHolders(netip.AddrPort, netip.AddrPort) ([]PortHolder, error) {
	return nil, ErrListenerInspectionUnavailable
}
