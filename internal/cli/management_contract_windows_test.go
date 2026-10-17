// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestManagementContractWindowsSecret validates what Windows
// `enterprise secret set`, `status` and `remove` print with --json.
func TestManagementContractWindowsSecret(t *testing.T) {
	schemas := contracttest.Compile(t)
	windowsSecretTestHarness(t)
	const value = "contract-test-credential-value"

	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, value+"\r\n")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if strings.Contains(out, value) {
		t.Fatal("the credential value was printed")
	}
	if doc := schemas.Validate(t, "secret-result.schema.json", []byte(out)); doc["ok"] != true || doc["action"] != "set" {
		t.Fatalf("set result %s", out)
	}

	out, err = runWindowsSecretCommand(t, "status", enterpriseSecretOptions{json: true}, "")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if strings.Contains(out, value) {
		t.Fatal("the credential value was printed")
	}
	schemas.Validate(t, "secret-result.schema.json", []byte(out))

	out, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key", json: true}, "")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	schemas.Validate(t, "secret-result.schema.json", []byte(out))

	t.Run("failures print one document", func(t *testing.T) {
		opts := enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}
		notElevated := func(managedHost bool) func() {
			return func() {
				windowsSecretIsElevated = func() bool { return false }
				managedHostWindowsStandalone = func() (string, bool) {
					if managedHost {
						return `HKLM\` + WindowsEnterpriseMarkerKey, true
					}
					return "", false
				}
			}
		}
		cases := map[string]struct {
			setup func()
			opts  enterpriseSecretOptions
			exit  int
		}{
			"not elevated, managed":   {notElevated(true), opts, enterprisestatus.WindowsExitAccessDenied},
			"not elevated, unmanaged": {notElevated(false), opts, windowsSecretExitFailure},
			"bad name":                {func() {}, enterpriseSecretOptions{name: "BAD", fromStdin: true, json: true}, windowsSecretExitInvalid},
			"not installed":           {func() { windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil } }, opts, windowsSecretExitFailure},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				savedElevated, savedInstalled, savedManaged := windowsSecretIsElevated, windowsSecretDeploymentInstalled, managedHostWindowsStandalone
				t.Cleanup(func() {
					windowsSecretIsElevated, windowsSecretDeploymentInstalled, managedHostWindowsStandalone = savedElevated, savedInstalled, savedManaged
				})
				tc.setup()
				out, err := runWindowsSecretCommand(t, "set", tc.opts, value+"\r\n")
				doc := schemas.Validate(t, "secret-result.schema.json", []byte(out))
				requireExit(t, doc, commandExitCode(err), tc.exit)
				if strings.Contains(out, value) {
					t.Fatal("the credential value was printed")
				}
			})
		}
	})
}

// TestManagementContractWindowsSecretEveryVerbAndFailure runs set, remove
// and status through their command with --json for every failure class:
// stdout holds exactly one secret-result document, stderr nothing, and the
// exit code is the document's. A standard account's `secret status --json`
// printed only its sentence on stderr (mgmt-agent-api GAP-0029). status
// takes no lock and needs no deployment, so it answers "not installed" and
// "lock busy" with its listing.
func TestManagementContractWindowsSecretEveryVerbAndFailure(t *testing.T) {
	schemas := contracttest.Compile(t)
	const value = "matrix-credential-value"
	verbs := []string{"set", "remove", "status"}
	valid := map[string][]string{
		"set":    {"--name", "ai-defense-api-key", "--from-stdin", "--json"},
		"remove": {"--name", "ai-defense-api-key", "--json"},
		"status": {"--json"},
	}
	type outcome struct {
		code string // errors[0].code; "" is the status listing (exit 0)
		exit int
	}
	every := func(o outcome) map[string]outcome {
		return map[string]outcome{"set": o, "remove": o, "status": o}
	}
	listing := outcome{}
	unreadable := errors.New("the standalone deployment record cannot be read")
	for _, class := range []struct {
		name  string
		args  func(verb string) []string
		setup func(t *testing.T, host *windowsSecretLockEvents, layout managed.StandaloneLayout)
		want  map[string]outcome
	}{
		{name: "not elevated, managed",
			setup: func(*testing.T, *windowsSecretLockEvents, managed.StandaloneLayout) {
				windowsSecretIsElevated = func() bool { return false }
				managedHostWindowsStandalone = func() (string, bool) { return `HKLM\` + WindowsEnterpriseMarkerKey, true }
			},
			want: every(outcome{"elevation_required", enterprisestatus.WindowsExitAccessDenied})},
		{name: "not elevated, unmanaged",
			setup: func(*testing.T, *windowsSecretLockEvents, managed.StandaloneLayout) {
				windowsSecretIsElevated = func() bool { return false }
			},
			want: every(outcome{"elevation_required", windowsSecretExitFailure})},
		{name: "bad name",
			// status has no --name: passing one is a flag error.
			args: func(verb string) []string {
				if verb == "status" {
					return []string{"--name", "BAD", "--json"}
				}
				return append([]string{"--name", "BAD"}, valid[verb][2:]...)
			},
			want: every(outcome{"invalid_arguments", windowsSecretExitInvalid})},
		{name: "bad flag",
			args: func(verb string) []string { return append(append([]string{}, valid[verb]...), "--bogus") },
			want: every(outcome{"invalid_arguments", windowsSecretExitInvalid})},
		{name: "not installed",
			setup: func(*testing.T, *windowsSecretLockEvents, managed.StandaloneLayout) {
				windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil }
			},
			want: map[string]outcome{"set": {"not_installed", windowsSecretExitFailure}, "remove": {"not_installed", windowsSecretExitFailure}, "status": listing}},
		{name: "lock busy",
			setup: func(_ *testing.T, host *windowsSecretLockEvents, _ managed.StandaloneLayout) {
				host.bundleErr = errWindowsBundleStoreBusy
			},
			want: map[string]outcome{"set": {"lifecycle_busy", enterprisestatus.WindowsExitBusy}, "remove": {"lifecycle_busy", enterprisestatus.WindowsExitBusy}, "status": listing}},
		{name: "corrupt deployment",
			setup: func(*testing.T, *windowsSecretLockEvents, managed.StandaloneLayout) {
				windowsSecretLayout = func() (managed.StandaloneLayout, error) { return managed.StandaloneLayout{}, unreadable }
				windowsSecretDeploymentInstalled = func() (bool, error) { return false, unreadable }
			},
			want: every(outcome{"state_invalid", windowsSecretExitFailure})},
		{name: "corrupt store",
			// A file where the secrets folder belongs: status cannot list it.
			setup: func(t *testing.T, _ *windowsSecretLockEvents, layout managed.StandaloneLayout) {
				if err := os.WriteFile(layout.SecretsDir, []byte("not a folder"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]outcome{"status": {"state_invalid", windowsSecretExitFailure}}},
	} {
		for _, verb := range verbs {
			want, ok := class.want[verb]
			if !ok {
				continue
			}
			t.Run(class.name+"/"+verb, func(t *testing.T) {
				layout := managed.StandaloneLayout{GOOS: "windows", SecretsDir: filepath.Join(t.TempDir(), "secrets"), LifecycleDir: t.TempDir()}
				host := stubWindowsSecretHost(t, layout)
				if class.setup != nil {
					class.setup(t, host, layout)
				}
				args := valid[verb]
				if class.args != nil {
					args = class.args(verb)
				}
				windowsSecretRawArgs = func() []string { return args }
				cmd := newEnterpriseSecretCommand(verb, "matrix")
				var stdout, stderr bytes.Buffer
				cmd.SetOut(&stdout)
				cmd.SetErr(&stderr)
				cmd.SetIn(strings.NewReader(value))
				cmd.SetArgs(args)
				err := cmd.Execute()
				if stderr.Len() != 0 {
					t.Fatalf("%v: stderr %q, want nothing (the document carries the error); stdout %q", args, stderr.String(), stdout.String())
				}
				if strings.Contains(stdout.String(), value) {
					t.Fatal("the credential value was printed")
				}
				doc := schemas.Validate(t, "secret-result.schema.json", stdout.Bytes())
				requireExit(t, doc, commandExitCode(err), want.exit)
				if want.code == "" {
					if err != nil || doc["secrets"] == nil {
						t.Fatalf("%v: want the status listing, got %v %s", args, err, stdout.String())
					}
					return
				}
				var code any
				if errs, _ := doc["errors"].([]any); len(errs) > 0 {
					if first, ok := errs[0].(map[string]any); ok {
						code = first["code"]
					}
				}
				if doc["ok"] != false || doc["action"] != verb || code != want.code {
					t.Fatalf("%v: document %s, want action %s code %s", args, stdout.String(), verb, want.code)
				}
				for _, event := range host.events {
					if event == "restart" {
						t.Fatal("the gateway restarted after a refusal")
					}
				}
			})
		}
	}
}
