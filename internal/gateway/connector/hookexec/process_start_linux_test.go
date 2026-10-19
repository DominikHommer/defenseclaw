// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import "testing"

func TestParseProcStatStartTicks(t *testing.T) {
	// The command name may hold spaces and parentheses.
	stat := "4242 (a b) (c)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 19 20\n"
	if got, ok := parseProcStatStartTicks(stat); !ok || got != 987654 {
		t.Fatalf("parseProcStatStartTicks = %d, %v; want 987654", got, ok)
	}
	for _, bad := range []string{"", "4242 no-paren S 1", "4242 (x) S 1 2 3", "4242 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 -5"} {
		if _, ok := parseProcStatStartTicks(bad); ok {
			t.Errorf("parseProcStatStartTicks(%q) accepted a malformed line", bad)
		}
	}
}
