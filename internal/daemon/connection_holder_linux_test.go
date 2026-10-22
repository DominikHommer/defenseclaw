// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The kernel's TCP tables list both ends of a loopback connection, the
// listener and connections still in a listen queue (inode 0). Only the
// established socket at the server address whose peer is the client is the
// connection's server end; an IPv4 connection a dual-stack listener
// accepted is listed with IPv4-mapped addresses in tcp6.
func TestProcConnectionHoldersFindTheServerEnd(t *testing.T) {
	root := t.TempDir()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	writeFile(t, filepath.Join(root, "net", "tcp"), header+
		// the listener 127.0.0.1:18970
		"   0: 0100007F:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 100 1\n"+
		// the client end 127.0.0.1:40000 -> 127.0.0.1:18970
		"   1: 0100007F:9C40 0100007F:4A1A 01 00000000:00000000 00:00000000 00000000  1000        0 200 1\n"+
		// a connection from 127.0.0.1:40001 still in the listen queue
		"   2: 0100007F:4A1A 0100007F:9C41 01 00000000:00000000 00:00000000 00000000     0        0 0 1\n")
	writeFile(t, filepath.Join(root, "net", "tcp6"), header+
		// the server end ::ffff:127.0.0.1:18970 <- ::ffff:127.0.0.1:40000
		"   0: 0000000000000000FFFF00000100007F:4A1A 0000000000000000FFFF00000100007F:9C40 01 00000000:00000000 00:00000000 00000000  1001        0 300 1\n")
	for pid, inode := range map[string]string{"10": "100", "20": "200", "30": "300"} {
		if err := os.MkdirAll(filepath.Join(root, pid, "fd"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(root, pid, "fd", "3")); err != nil {
			t.Fatal(err)
		}
	}
	server := netip.MustParseAddrPort("127.0.0.1:18970")
	holders, err := findProcConnectionHolders(root, server, netip.MustParseAddrPort("127.0.0.1:40000"))
	if err != nil || len(holders) != 1 || holders[0].PID != 30 || holders[0].UID != 1001 {
		t.Fatalf("server end = %+v, %v; want PID 30", holders, err)
	}
	if _, err := findProcConnectionHolders(root, server, netip.MustParseAddrPort("127.0.0.1:40001")); !errors.Is(err, ErrNoConnection) {
		t.Fatalf("a connection in the listen queue: %v", err)
	}
	if _, err := findProcConnectionHolders(root, server, netip.MustParseAddrPort("127.0.0.1:40002")); !errors.Is(err, ErrNoConnection) {
		t.Fatalf("no connection: %v", err)
	}
	// A socket no readable process holds is one holder with PID 0.
	if err := os.RemoveAll(filepath.Join(root, "30")); err != nil {
		t.Fatal(err)
	}
	holders, err = findProcConnectionHolders(root, server, netip.MustParseAddrPort("127.0.0.1:40000"))
	if err != nil || len(holders) != 1 || holders[0].PID != 0 {
		t.Fatalf("an unreadable holder = %+v, %v", holders, err)
	}
	if _, err := findProcConnectionHolders(t.TempDir(), server, netip.MustParseAddrPort("127.0.0.1:40000")); !errors.Is(err, ErrListenerInspectionUnavailable) {
		t.Fatalf("no TCP tables: %v", err)
	}
}
