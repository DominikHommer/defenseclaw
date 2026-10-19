// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFixedHookSchemasAreClosedAndCommandsStayJSON(t *testing.T) {
	seen := map[string]bool{}
	for _, value := range Cases() {
		if seen[value.Name] || value.Name == "" {
			t.Fatal("duplicate/empty fixed schema")
		}
		seen[value.Name] = true
		for _, phase := range []byte{'A', 'B', 'L'} {
			raw, err := value.Payload(phase)
			if err != nil || !json.Valid(raw) || bytes.Contains(raw, []byte("COMMAND")) {
				t.Fatal("invalid fixed schema", value.Name)
			}
		}
		if _, err := value.Payload('X'); err == nil {
			t.Fatal("unknown command admitted")
		}
	}
	if len(seen) != 12 {
		t.Fatal("fixed inventory changed")
	}
	if _, err := Lookup("unknown"); err == nil {
		t.Fatal("unknown connector admitted")
	}
}
