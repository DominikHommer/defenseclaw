// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0553: when remove-all reports a user's registrations as pending (the
// user's home is not available, or is gone with a removed AD mobile
// account), a managed uninstall without --purge warns per_user_hooks_remaining
// for that user and agent and goes on: the binaries and the deployment go.
func TestUninstallWarnsAndGoesOnForAPerUserHomeThatIsNotAvailable(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"pending":["dcad-r102-eng1/hermes"]}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall})
			requireOK(t, done)
			got := messagesOf(done.Warnings, codePerUserHooks)
			if !strings.Contains(got, "hermes hooks for user dcad-r102-eng1 were not removed because that account's home is not available") {
				t.Fatalf("the uninstall does not warn for the user whose home is not available: %q", got)
			}
			if messagesOf(done.Errors, codePerUserHooks) != "" || messagesOf(done.Errors, codeUninstallIncomplete) != "" {
				t.Fatalf("a home that is not available must not stop the uninstall: %+v", done.Errors)
			}
			if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || exists(h.env.deploymentPath()) {
				t.Fatal("the uninstall did not remove the binaries and the deployment record")
			}
		})
	}
}
