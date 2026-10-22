// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrNoConnection is returned by FindConnectionHolders when no process
// holds the connection: it is gone, or it still waits in a listen queue for
// a process to accept it.
var ErrNoConnection = errors.New("no process holds the connection")

// FindConnectionHolders describes every process that holds the established
// TCP socket whose local address is local and whose peer is remote. For a
// connection this computer made to local from remote, that is the socket a
// server accepted: whoever holds it reads what the client sends, whichever
// process holds the listener now. A socket whose process this account cannot
// see is one holder with PID 0; Windows names the one owning process of any
// account. It returns ErrNoConnection when no process holds such a socket
// and ErrListenerInspectionUnavailable when the platform cannot tell.
func FindConnectionHolders(local, remote netip.AddrPort) ([]PortHolder, error) {
	local, remote = unmappedAddrPort(local), unmappedAddrPort(remote)
	if !local.Addr().IsValid() || !remote.Addr().IsValid() || local.Port() == 0 || remote.Port() == 0 {
		return nil, fmt.Errorf("%w: invalid connection %s from %s", ErrListenerInspectionUnavailable, local, remote)
	}
	return findConnectionHolders(local, remote)
}

// unmappedAddrPort is addr with an IPv4-mapped IPv6 address as its IPv4
// address and no zone, the form the connection tables are compared in.
func unmappedAddrPort(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap().WithZone(""), addr.Port())
}
