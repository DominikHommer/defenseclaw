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
// user's home is not available), the registrations have not been proved gone.
// Keep the binaries they call and the deployment needed to retry cleanup.
func TestUninstallRetainsDeploymentForAPerUserHomeThatIsNotAvailable(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"pending":["sample-user/hermes"]}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall})
			if done.OK || messagesOf(done.Errors, codePerUserHooks) == "" || messagesOf(done.Errors, codeUninstallIncomplete) == "" {
				t.Fatalf("pending registrations must retain the deployment: %+v", done)
			}
			got := messagesOf(done.Errors, codePerUserHooks)
			if !strings.Contains(got, "hermes hooks for user sample-user were not removed because that account's home is not available") {
				t.Fatalf("the uninstall does not warn for the user whose home is not available: %q", got)
			}
			if !exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || !exists(h.env.deploymentPath()) {
				t.Fatal("the uninstall lost the binaries or its retryable deployment record")
			}
		})
	}
}

// GAP-0553: remove-all reports the pending cleanup of a removed account
// with a reason that names its recorded home and a remedy. The uninstall
// keeps the deployment and reports that reason with the retry command.
func TestUninstallRetainsDeploymentForARemovedAccountsPendingHooks(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			reason := "the directory gives the account no home (/var/empty), so it looks removed, but its recorded home /Users/dcad-kept is not gone and may still hold DefenseClaw's entries; remove them from the hermes config in /Users/dcad-kept, or delete that home if the account is gone"
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":0,"pending":["dcad-kept/hermes: ` + reason + `"]}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall})
			if done.OK || messagesOf(done.Errors, codePerUserHooks) == "" || messagesOf(done.Errors, codeUninstallIncomplete) == "" {
				t.Fatalf("pending registrations must retain the deployment: %+v", done)
			}
			got := messagesOf(done.Errors, codePerUserHooks)
			if !strings.Contains(got, "DefenseClaw's hermes hooks for user dcad-kept were not removed: "+reason) || strings.Contains(got, "once it is") {
				t.Fatalf("the uninstall does not warn with the removed account's reason: %q", got)
			}
			if !exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || !exists(h.env.deploymentPath()) {
				t.Fatal("the uninstall lost the binaries or its retryable deployment record")
			}
		})
	}
}
