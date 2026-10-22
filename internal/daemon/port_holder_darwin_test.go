// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// lsof -Fn lists the process (p), the descriptors (f) and the socket names
// (n); only the names are listen addresses.
func TestParseLsofListenAddrs(t *testing.T) {
	found := parseLsofListenAddrs("p321\nf5\nn127.0.0.1:18970\nf6\nn*:4000\nf7\nn[::1]:18972\nf8\nnnot-an-address\n")
	var got []string
	for _, listener := range found {
		got = append(got, net.JoinHostPort(listener.IP.String(), strconv.Itoa(listener.Port)))
	}
	if strings.Join(got, ",") != "127.0.0.1:18970,[::]:4000,[::1]:18972" {
		t.Fatalf("listen addresses = %v", got)
	}
}

func TestProcessTCPListenersFindsAListenerOfThisProcess(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	found, err := ProcessTCPListeners(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(found, func(l TCPListenAddr) bool { return l.Port == port && l.IP.IsLoopback() }) {
		t.Fatalf("listeners of this process %v do not include 127.0.0.1:%d", found, port)
	}
}
