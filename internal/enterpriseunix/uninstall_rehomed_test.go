//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterpriseunix

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallExplainsHowToClearAFailedRehomedCleanup(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":false,"removed":0,"failed":["sample-user/hermes: recorded home /home/sample-user-old differs from the current home /home/sample-user-new"]}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall})
			requireError(t, done, codePerUserHooks)
			requireError(t, done, codeUninstallIncomplete)
			message := messagesOf(done.Errors, codePerUserHooks)
			for _, want := range []string{"fix the account's home", "existing directory it owns", "without symlinks or group/other write", "remove the account", "rerun"} {
				if !strings.Contains(message, want) {
					t.Fatalf("failed cleanup remedy %q lacks %q", message, want)
				}
			}
			if strings.Contains(message, "remove DefenseClaw's entries from that account") {
				t.Fatalf("failed cleanup remedy still suggests a config edit: %q", message)
			}
		})
	}
}

func TestUninstallCompletesAfterARehomedCleanupWasRemoved(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.Runner = removeAllRunner{Runner: h.runner, answer: func(string) (CommandResult, error) {
				return CommandResult{Stdout: []byte(`{"ok":true,"removed":1,"failed":[]}`)}, nil
			}}
			done := h.run(Options{Action: ActionUninstall})
			requireOK(t, done)
			if messagesOf(done.Errors, codePerUserHooks) != "" || messagesOf(done.Errors, codeUninstallIncomplete) != "" {
				t.Fatalf("completed re-home cleanup blocked uninstall: %+v", done.Errors)
			}
			if exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) || exists(h.env.deploymentPath()) {
				t.Fatal("uninstall kept the binaries or deployment record")
			}
		})
	}
}
