// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Another service listening on the same port at a different address is not
// the holder of the configured gateway address.
func TestProcPortHolderMatchesTheConfiguredAddress(t *testing.T) {
	root := t.TempDir()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	tables := map[string]string{
		// [::1]:8000 held by PID 20 (uid 1001) is listed first.
		"tcp6": header + "   0: 00000000000000000000000001000000:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 222 1\n",
		// 127.0.0.1:8000 held by PID 10 (uid 1000).
		"tcp": header + "   0: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1\n",
	}
	for name, body := range tables {
		writeFile(t, filepath.Join(root, "net", name), body)
	}
	for pid, inode := range map[string]string{"10": "111", "20": "222"} {
		writeFile(t, filepath.Join(root, pid, "comm"), "proc"+pid+"\n")
		if err := os.MkdirAll(filepath.Join(root, pid, "fd"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(root, pid, "fd", "3")); err != nil {
			t.Fatal(err)
		}
	}
	for host, want := range map[string]int{"127.0.0.1": 10, "::1": 20} {
		holder, err := findProcPortHolder(root, host, 8000)
		if err != nil || holder.PID != want || holder.UID != 1000+want/10-1 {
			t.Fatalf("holder of %s:8000 = %+v, %v; want PID %d", host, holder, err, want)
		}
	}
}

// Under systemd socket activation PID 1 and the gateway service hold the
// same listening socket. FindPortHolder names PID 1 only; FindPortHolders
// names both, so a caller can find the service among them.
func TestProcPortHoldersListEveryProcessHoldingTheSocket(t *testing.T) {
	root := t.TempDir()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	writeFile(t, filepath.Join(root, "net", "tcp"), header+
		"   0: 0100007F:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 333 1\n")
	for pid, fds := range map[string][]string{
		"1":    {"socket:[999]", "socket:[333]"},
		"4242": {"socket:[333]", "socket:[333]"},
		"77":   {"socket:[444]"},
	} {
		writeFile(t, filepath.Join(root, pid, "comm"), "proc"+pid+"\n")
		if err := os.MkdirAll(filepath.Join(root, pid, "fd"), 0o700); err != nil {
			t.Fatal(err)
		}
		for i, target := range fds {
			if err := os.Symlink(target, filepath.Join(root, pid, "fd", string(rune('3'+i)))); err != nil {
				t.Fatal(err)
			}
		}
	}
	first, err := findProcPortHolder(root, "127.0.0.1", 18970)
	if err != nil || first.PID != 1 {
		t.Fatalf("first holder = %+v, %v; want PID 1", first, err)
	}
	holders, err := findProcPortHolders(root, "127.0.0.1", 18970)
	if err != nil || len(holders) != 2 || holders[0].PID != 1 || holders[1].PID != 4242 || holders[1].UID != 0 ||
		holders[1].Command != "proc4242" {
		t.Fatalf("holders = %+v, %v; want PID 1 and 4242 once each", holders, err)
	}
	if _, err := findProcPortHolders(root, "127.0.0.1", 18971); err != ErrNoListener {
		t.Fatalf("no listener: %v", err)
	}
	// A socket no readable process holds is one unnamed holder.
	writeFile(t, filepath.Join(root, "net", "tcp"), header+
		"   0: 0100007F:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 555 1\n")
	holders, err = findProcPortHolders(root, "127.0.0.1", 18970)
	if err != nil || len(holders) != 1 || holders[0].PID != 0 || holders[0].UID != 1001 {
		t.Fatalf("unreadable holder = %+v, %v", holders, err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A process's listeners are the LISTEN sockets among its own descriptors,
// read from the TCP tables of its network namespace: not another
// process's listener, and not its connected sockets.
func TestProcProcessTCPListenersListsOnlyTheProcessListeners(t *testing.T) {
	root := t.TempDir()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	writeFile(t, filepath.Join(root, "10", "net", "tcp"), header+
		// 127.0.0.1:18970 LISTEN, held by PID 10.
		"   0: 0100007F:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1\n"+
		// 0.0.0.0:4000 LISTEN, held by PID 10.
		"   1: 00000000:0FA0 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 112 1\n"+
		// 127.0.0.1:18971 LISTEN, held by PID 20 only.
		"   2: 0100007F:4A1B 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 222 1\n"+
		// An established connection of PID 10.
		"   3: 0100007F:9C40 0100007F:4A1A 01 00000000:00000000 00:00000000 00000000  1000        0 113 1\n")
	writeFile(t, filepath.Join(root, "10", "net", "tcp6"), header+
		// [::1]:18972 LISTEN, held by PID 10.
		"   0: 00000000000000000000000001000000:4A1C 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 114 1\n")
	if err := os.MkdirAll(filepath.Join(root, "10", "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	for fd, target := range map[string]string{"3": "socket:[111]", "4": "socket:[112]", "5": "socket:[113]", "6": "socket:[114]", "7": "/dev/null"} {
		if err := os.Symlink(target, filepath.Join(root, "10", "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
	found, err := procProcessTCPListeners(root, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, listener := range found {
		got = append(got, net.JoinHostPort(listener.IP.String(), strconv.Itoa(listener.Port)))
	}
	if strings.Join(got, ",") != "127.0.0.1:18970,0.0.0.0:4000,[::1]:18972" {
		t.Fatalf("listeners of PID 10 = %v", got)
	}
	if _, err := procProcessTCPListeners(root, 30); !errors.Is(err, ErrListenerInspectionUnavailable) {
		t.Fatalf("a process whose descriptors cannot be read: %v", err)
	}
}
