// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The managed native hook resolves a call's write targets as its connector's
// gateway profile reads the call: for Copilot the camelCase toolName and
// toolArgs, not a decoy tool_name beside them.
func TestManagedHookWriteEvidenceReadsTheConnectorsCall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the managed hook sends write evidence on Linux and macOS only")
	}
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cwd, "notes.txt")
	patch := "*** Begin Patch\n*** Update File: " + target + "\n@@\n-a\n+b\n*** End Patch\n"
	payload, err := json.Marshal(map[string]any{"cwd": cwd, "toolName": "apply_patch", "tool_name": "read_file", "toolArgs": patch})
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{}
	setHookRequestFacts(header, Options{Connector: "copilot", ManagedEnterprise: true}, payload)
	targets, ok := hookpaths.Decode(header.Get(hookpaths.Header))
	if !ok {
		t.Fatal("no decodable write evidence")
	}
	if _, listed := targets[target]; !listed {
		t.Fatalf("patch target missing from the evidence: %v", targets)
	}
}
