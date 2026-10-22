// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// findPortHolder asks the system lsof for the LISTEN socket on port that
// serves host. lsof sees this account's processes; another account's
// listener is reported as unavailable.
func findPortHolder(host string, port int) (PortHolder, error) {
	holders, err := findPortHolders(host, port)
	if err != nil {
		return PortHolder{UID: -1}, err
	}
	return holders[0], nil
}

func findPortHolders(host string, port int) ([]PortHolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(
		ctx, "/usr/sbin/lsof", "-nP", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fpcun",
	).Output()
	if err != nil && len(output) == 0 {
		// lsof exits 1 when it lists nothing.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, ErrNoListener
		}
		return nil, ErrListenerInspectionUnavailable
	}
	holders := parseLsofPortHolders(string(output), host)
	if len(holders) == 0 {
		return nil, ErrNoListener
	}
	return holders, nil
}

// parseLsofPortHolder picks, from lsof -Fpcun output, the first process with
// a listening socket that serves host.
func parseLsofPortHolder(output, host string) (PortHolder, error) {
	if holders := parseLsofPortHolders(output, host); len(holders) > 0 {
		return holders[0], nil
	}
	return PortHolder{UID: -1}, ErrNoListener
}

// parseLsofPortHolders lists, from lsof -Fpcun output, every process with a
// listening socket that serves host, once each. Process fields (p, c, u)
// precede the names (n) of that process's sockets.
func parseLsofPortHolders(output, host string) []PortHolder {
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
			if !listed && holder.PID > 0 && listenerServesHost(host, lsofListenIP(value)) {
				holders = append(holders, holder)
				listed = true
			}
		}
	}
	return holders
}

// lsofListenIP is the bound address of an lsof socket name such as
// "127.0.0.1:18970", "[::1]:18970" or "*:18970" (unspecified).
func lsofListenIP(name string) net.IP {
	host, _, err := net.SplitHostPort(name)
	if err != nil {
		return nil
	}
	if host == "*" {
		return net.IPv6unspecified
	}
	return net.ParseIP(host)
}
