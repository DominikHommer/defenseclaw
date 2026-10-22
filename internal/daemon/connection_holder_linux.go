// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"bufio"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func findConnectionHolders(local, remote netip.AddrPort) ([]PortHolder, error) {
	return findProcConnectionHolders("/proc", local, remote)
}

// findProcConnectionHolders reads the kernel's TCP tables for the
// established socket at local whose peer is remote, then finds the
// processes that hold it (procSocketHolders). A connection that still waits
// in a listen queue has no socket inode yet (0): no process holds it.
func findProcConnectionHolders(procRoot string, local, remote netip.AddrPort) ([]PortHolder, error) {
	holder := PortHolder{UID: -1}
	inodes := map[string]struct{}{}
	inspected := false
	for _, table := range []string{"tcp", "tcp6"} {
		file, err := os.Open(filepath.Join(procRoot, "net", table))
		if err != nil {
			continue
		}
		inspected = true
		scanner := bufio.NewScanner(file)
		scanner.Scan() // header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			// 01 is TCP_ESTABLISHED.
			if len(fields) < 10 || fields[3] != "01" || fields[9] == "0" {
				continue
			}
			if procAddrPort(fields[1]) != local || procAddrPort(fields[2]) != remote {
				continue
			}
			if uid, err := strconv.Atoi(fields[7]); err == nil && holder.UID < 0 {
				holder.UID = uid
			}
			inodes["socket:["+fields[9]+"]"] = struct{}{}
		}
		_ = file.Close()
	}
	if !inspected {
		return nil, ErrListenerInspectionUnavailable
	}
	if len(inodes) == 0 {
		return nil, ErrNoConnection
	}
	return procSocketHolders(procRoot, inodes, holder), nil
}

// procAddrPort decodes a /proc/net/tcp{,6} ADDRESS:PORT, an IPv4-mapped
// IPv6 address as its IPv4 address. It is the zero AddrPort when malformed.
func procAddrPort(field string) netip.AddrPort {
	addrHex, portHex, ok := strings.Cut(field, ":")
	if !ok {
		return netip.AddrPort{}
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	addr, valid := netip.AddrFromSlice(procAddrIP(addrHex))
	if err != nil || !valid {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port))
}
