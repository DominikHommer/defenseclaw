// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || windows

package daemon

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// connectionHolderHelperEnv makes this test binary a process that accepts
// one connection on a loopback port and holds it
// (TestConnectionHolderHelperProcess).
const connectionHolderHelperEnv = "DEFENSECLAW_TEST_CONNECTION_HOLDER_DIR"

func TestConnectionHolderHelperProcess(*testing.T) {
	dir := os.Getenv(connectionHolderHelperEnv)
	if dir == "" {
		return
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if os.WriteFile(filepath.Join(dir, "port.tmp"), []byte(port), 0o600) != nil ||
		os.Rename(filepath.Join(dir, "port.tmp"), filepath.Join(dir, "port")) != nil {
		os.Exit(3)
	}
	conn, err := listener.Accept()
	if err != nil {
		os.Exit(4)
	}
	_ = listener.Close()
	buf := make([]byte, 1)
	_, _ = conn.Read(buf) // hold the connection until the client closes it
	os.Exit(0)
}

// connectionEnds is the server end (the remote address) and the client end
// (the local address) of conn.
func connectionEnds(conn net.Conn) (netip.AddrPort, netip.AddrPort) {
	return conn.RemoteAddr().(*net.TCPAddr).AddrPort(), conn.LocalAddr().(*net.TCPAddr).AddrPort()
}

// waitConnectionHolders asks until the operating system lists holders of
// the server end of conn, or no longer finds it.
func waitConnectionHolders(t *testing.T, conn net.Conn, want error) []PortHolder {
	t.Helper()
	server, client := connectionEnds(conn)
	deadline := time.Now().Add(10 * time.Second)
	for {
		holders, err := FindConnectionHolders(server, client)
		if want == nil && err == nil && len(holders) > 0 && holders[0].PID > 0 {
			return holders
		}
		if want != nil && errors.Is(err, want) {
			return holders
		}
		if time.Now().After(deadline) {
			t.Fatalf("holders of %s from %s = %+v, %v", server, client, holders, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// FindConnectionHolders names the process that accepted a connection: the
// holder of its server end, not of its client end, and not whoever holds
// the listener now. A connection that is gone has none.
func TestFindConnectionHoldersNamesTheProcessThatAccepted(t *testing.T) {
	// This process accepted: it holds both ends.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	holders := waitConnectionHolders(t, conn, nil)
	if len(holders) != 1 || holders[0].PID != os.Getpid() {
		t.Fatalf("holders of a connection this process accepted = %+v", holders)
	}
	_ = accepted.Close()
	_ = conn.Close()
	waitConnectionHolders(t, conn, ErrNoConnection)

	// Another process accepted; this process holds only the client end.
	dir := t.TempDir()
	helper := exec.Command(os.Args[0], "-test.run=^TestConnectionHolderHelperProcess$")
	helper.Env = append(os.Environ(), connectionHolderHelperEnv+"="+dir)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	var port []byte
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if port, err = os.ReadFile(filepath.Join(dir, "port")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the helper did not listen")
		}
	}
	conn, err = net.Dial("tcp4", net.JoinHostPort("127.0.0.1", string(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	holders = waitConnectionHolders(t, conn, nil)
	if len(holders) != 1 || holders[0].PID != helper.Process.Pid {
		t.Fatalf("holders of a connection the helper (PID %d) accepted = %+v", helper.Process.Pid, holders)
	}

	// The same socket asked about from the other end is this process's.
	server, client := connectionEnds(conn)
	if mine, err := FindConnectionHolders(client, server); err != nil || len(mine) != 1 || mine[0].PID != os.Getpid() {
		t.Fatalf("holders of the client end = %+v, %v", mine, err)
	}
	if _, err := FindConnectionHolders(netip.AddrPort{}, client); !errors.Is(err, ErrListenerInspectionUnavailable) {
		t.Fatalf("an invalid connection: %v", err)
	}
}
