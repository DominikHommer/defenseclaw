// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// A '#' that is code in some interpreter must not hide a later writer call.
func TestInterpreterCodePositionHashToken(t *testing.T) {
	for code, want := range map[string]bool{
		`class A{#p=1}; require("fs").appendFileSync("out.txt","k")`: true,
		`$#a; open(F, ">>", "out.txt")`:                              true,
		"# open(\"out.txt\",\"w\")\nprint(1)":                        false,
		"print(1)  # open(\"out.txt\",\"w\")":                        false,
	} {
		marker := "open("
		if strings.Contains(code, "appendFileSync") {
			marker = "appendFileSync"
		}
		if got := interpreterCodePosition(code, strings.Index(code, marker)); got != want {
			t.Errorf("interpreterCodePosition(%q) = %v, want %v", code, got, want)
		}
	}
}
