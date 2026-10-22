// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func findPortHolder(host string, port int) (PortHolder, error) {
	return findProcPortHolder("/proc", host, port)
}

func findPortHolders(host string, port int) ([]PortHolder, error) {
	return findProcPortHolders("/proc", host, port)
}

// findProcPortHolder reads the kernel's TCP tables for a LISTEN socket on
// port that serves host, then finds the process that owns that socket among
// the processes whose descriptors this account may read.
func findProcPortHolder(procRoot, host string, port int) (PortHolder, error) {
	holders, err := findProcPortHolders(procRoot, host, port)
	if len(holders) == 0 {
		return PortHolder{UID: -1}, err
	}
	return holders[0], err
}

// findProcPortHolders is findProcPortHolder for every process holding the
// socket, in /proc order. A socket no readable process holds is one holder
// with PID 0.
func findProcPortHolders(procRoot, host string, port int) ([]PortHolder, error) {
	holder := PortHolder{UID: -1}
	inodes := map[string]struct{}{}
	for _, table := range []string{"tcp", "tcp6"} {
		file, err := os.Open(filepath.Join(procRoot, "net", table))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Scan() // header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			addrHex, portHex, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			if value, err := strconv.ParseUint(portHex, 16, 16); err != nil || int(value) != port {
				continue
			}
			if !listenerServesHost(host, procAddrIP(addrHex)) {
				continue
			}
			if uid, err := strconv.Atoi(fields[7]); err == nil && holder.UID < 0 {
				holder.UID = uid
			}
			inodes["socket:["+fields[9]+"]"] = struct{}{}
		}
		_ = file.Close()
	}
	if len(inodes) == 0 {
		return nil, ErrNoListener
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return []PortHolder{holder}, nil
	}
	var holders []PortHolder
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(procRoot, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if _, ok := inodes[target]; ok {
				found := holder
				found.PID = pid
				if comm, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "comm")); err == nil {
					found.Command = strings.TrimSpace(string(comm))
				}
				holders = append(holders, found)
				break
			}
		}
	}
	if len(holders) == 0 {
		return []PortHolder{holder}, nil
	}
	return holders, nil
}

// procAddrIP decodes a /proc/net/tcp{,6} address: 32-bit words in host byte
// order. It returns nil for a malformed address.
func procAddrIP(addrHex string) net.IP {
	raw, err := hex.DecodeString(addrHex)
	if err != nil || (len(raw) != net.IPv4len && len(raw) != net.IPv6len) {
		return nil
	}
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:], binary.NativeEndian.Uint32(raw[i:]))
	}
	return net.IP(raw)
}
