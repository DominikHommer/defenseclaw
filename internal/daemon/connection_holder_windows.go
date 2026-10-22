// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDConnections = 4 // TCP_TABLE_OWNER_PID_CONNECTIONS
	mibTCPStateEstablished      = 5 // MIB_TCP_STATE_ESTAB
)

// findConnectionHolders names the process that owns the established socket
// at local whose peer is remote, from the owner-PID connection tables.
func findConnectionHolders(local, remote netip.AddrPort) ([]PortHolder, error) {
	var holders []PortHolder
	add := func(pid uint32, from, to netip.AddrPort) {
		if unmappedAddrPort(from) != local || unmappedAddrPort(to) != remote {
			return
		}
		for _, known := range holders {
			if known.PID == int(pid) {
				return
			}
		}
		holders = append(holders, PortHolder{PID: int(pid), UID: -1})
	}
	if err := walkExtendedTCPTable(windows.AF_INET, tcpTableOwnerPIDConnections, unsafe.Sizeof(tcp4OwnerPIDRow{}), func(row unsafe.Pointer) {
		r := (*tcp4OwnerPIDRow)(row)
		if r.State != mibTCPStateEstablished {
			return
		}
		localAddr := *(*[4]byte)(unsafe.Pointer(&r.LocalAddr))
		remoteAddr := *(*[4]byte)(unsafe.Pointer(&r.RemoteAddr))
		add(r.PID,
			netip.AddrPortFrom(netip.AddrFrom4(localAddr), windows.Ntohs(uint16(r.LocalPort))),
			netip.AddrPortFrom(netip.AddrFrom4(remoteAddr), windows.Ntohs(uint16(r.RemotePort))))
	}); err != nil {
		return nil, err
	}
	if err := walkExtendedTCPTable(windows.AF_INET6, tcpTableOwnerPIDConnections, unsafe.Sizeof(tcp6OwnerPIDRow{}), func(row unsafe.Pointer) {
		r := (*tcp6OwnerPIDRow)(row)
		if r.State != mibTCPStateEstablished {
			return
		}
		add(r.PID,
			netip.AddrPortFrom(netip.AddrFrom16(r.LocalAddr), windows.Ntohs(uint16(r.LocalPort))),
			netip.AddrPortFrom(netip.AddrFrom16(r.RemoteAddr), windows.Ntohs(uint16(r.RemotePort))))
	}); err != nil {
		return nil, err
	}
	if len(holders) == 0 {
		return nil, ErrNoConnection
	}
	return holders, nil
}
