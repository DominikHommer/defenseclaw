// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package agentprocess

import "testing"

func TestCompareMarksOrdersMarksOfOneBootOnly(t *testing.T) {
	cases := []struct {
		a, b  string
		order int
		ok    bool
	}{
		{"linux:b:100", "linux:b:200", -1, true},
		{"linux:b:200", "linux:b:100", 1, true},
		{"linux:b:100", "linux:b:100", 0, true},
		{"windows::134000000000000000", "windows::133000000000000000", 1, true},
		{"linux:a:100", "linux:b:200", 0, false},
		{"linux:b:100", "darwin:b:200", 0, false},
		{"linux:b:x", "linux:b:200", 0, false},
		{"linux:b:1:100", "linux:b:200", 0, false},
		{"", "linux:b:200", 0, false},
	}
	for _, tc := range cases {
		order, ok := CompareMarks(tc.a, tc.b)
		if order != tc.order || ok != tc.ok {
			t.Fatalf("CompareMarks(%q, %q) = %d, %v; want %d, %v", tc.a, tc.b, order, ok, tc.order, tc.ok)
		}
	}
}
