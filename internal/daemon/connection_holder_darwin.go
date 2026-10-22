// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"context"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// findConnectionHolders asks the system lsof for the established socket at
// local whose peer is remote. lsof sees this account's processes (root sees
// all); a connection that still waits in a listen queue belongs to none.
func findConnectionHolders(local, remote netip.AddrPort) ([]PortHolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(
		ctx, "/usr/sbin/lsof", "-nP", "-iTCP:"+strconv.Itoa(int(remote.Port())), "-sTCP:ESTABLISHED", "-Fpcun",
	).Output()
	if err != nil && len(output) == 0 {
		// lsof exits 1 when it lists nothing.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, ErrNoConnection
		}
		return nil, ErrListenerInspectionUnavailable
	}
	if holders := parseLsofConnectionHolders(string(output), local, remote); len(holders) > 0 {
		return holders, nil
	}
	return nil, ErrNoConnection
}

// parseLsofConnectionHolders lists, from lsof -Fpcun output, every process
// with a socket named local->remote, once each. Process fields (p, c, u)
// precede the names (n) of that process's sockets.
func parseLsofConnectionHolders(output string, local, remote netip.AddrPort) []PortHolder {
	var holders []PortHolder
	holder := PortHolder{UID: -1}
	listed := false
	for _, line := range strings.Split(output, "\n") {
		if len(line) < 2 {
			continue
		}
		value := line[1:]
		switch line[0] {
		case 'p':
			holder = PortHolder{UID: -1}
			holder.PID, _ = strconv.Atoi(value)
			listed = false
		case 'c':
			holder.Command = value
		case 'u':
			holder.UID, _ = strconv.Atoi(value)
		case 'n':
			from, to, ok := strings.Cut(value, "->")
			if !listed && ok && holder.PID > 0 && lsofAddrPort(from) == local && lsofAddrPort(to) == remote {
				holders = append(holders, holder)
				listed = true
			}
		}
	}
	return holders
}

// lsofAddrPort is an lsof socket address such as "127.0.0.1:18970" or
// "[::1]:18970"; the zero AddrPort when it is not one.
func lsofAddrPort(name string) netip.AddrPort {
	parsed, err := netip.ParseAddrPort(strings.TrimSpace(name))
	if err != nil {
		return netip.AddrPort{}
	}
	return unmappedAddrPort(parsed)
}
