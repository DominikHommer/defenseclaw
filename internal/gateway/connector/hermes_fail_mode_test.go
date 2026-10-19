// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-3 GAP-0269 (and GAP-0150): a per-user Hermes render keeps the
// resolved fail mode. The Windows native Hermes hook reads it from .hookcfg,
// so a closed or unset hook_fail_mode must be recorded as closed there, not
// downgraded to open; only an explicit open is recorded open. Secure Client
// keeps Hermes open (TestManagedStandaloneRenderKeepsClosed).
func TestPerUserHermesRenderRecordsTheResolvedFailMode(t *testing.T) {
	for _, tc := range []struct {
		name, mode, want string
	}{
		{name: "unset", mode: "", want: "closed"},
		{name: "closed", mode: "closed", want: "closed"},
		{name: "open", mode: "open", want: "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := SetupOpts{
				DataDir:      filepath.Join(dir, "dc"),
				APIAddr:      "127.0.0.1:18970",
				APIToken:     "tok-test",
				HookFailMode: tc.mode,
				WorkspaceDir: dir,
			}
			hermes := NewHermesConnector()
			if got := HookFailClosed(opts, hermes); got != (tc.want == "closed") {
				t.Fatalf("HookFailClosed = %v, want %v", got, tc.want == "closed")
			}
			hookDir := filepath.Join(dir, "hooks")
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, hermes); err != nil {
				t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(hookDir, hookConfigSidecarName))
			if err != nil {
				t.Fatalf("read %s: %v", hookConfigSidecarName, err)
			}
			var sidecar struct {
				FailModes map[string]string `json:"fail_modes"`
			}
			if err := json.Unmarshal(data, &sidecar); err != nil {
				t.Fatalf("decode %s: %v", hookConfigSidecarName, err)
			}
			if got := sidecar.FailModes["hermes"]; got != tc.want {
				t.Fatalf("%s fail_modes.hermes = %q, want %q", hookConfigSidecarName, got, tc.want)
			}
		})
	}
}
