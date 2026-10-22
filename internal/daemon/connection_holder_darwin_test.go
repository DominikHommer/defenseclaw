// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"net/netip"
	"testing"
)

// lsof lists both ends of a loopback connection; only the socket named
// server->client is its server end.
func TestLsofConnectionHoldersFindTheServerEnd(t *testing.T) {
	output := "p100\ncclient\nu501\nf7\nn127.0.0.1:40000->127.0.0.1:18970\n" +
		"p200\ncgateway\nu501\nf9\nn127.0.0.1:18970->127.0.0.1:40000\nf10\nn127.0.0.1:18970->127.0.0.1:40000\n" +
		"p300\ncother\nu502\nf4\nn[::ffff:127.0.0.1]:18970->[::ffff:127.0.0.1]:40000\n" +
		"p400\ncv6\nu501\nf5\nn[::1]:18970->[::1]:40000\n"
	server, client := netip.MustParseAddrPort("127.0.0.1:18970"), netip.MustParseAddrPort("127.0.0.1:40000")
	holders := parseLsofConnectionHolders(output, server, client)
	if len(holders) != 2 || holders[0].PID != 200 || holders[0].UID != 501 || holders[1].PID != 300 {
		t.Fatalf("server end holders = %+v; want PIDs 200 and 300", holders)
	}
	if holders := parseLsofConnectionHolders(output, netip.MustParseAddrPort("[::1]:18970"), netip.MustParseAddrPort("[::1]:40000")); len(holders) != 1 || holders[0].PID != 400 {
		t.Fatalf("IPv6 server end holders = %+v", holders)
	}
}
