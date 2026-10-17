// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestManagementContractWindowsBundleStatusDeliveryID drives the Windows
// apply with --delivery-id to a confirmed bundle and validates the
// `bundle status --json` and the public receipt files that follow
// (GAP-0001: current carries the delivery id).
func TestManagementContractWindowsBundleStatusDeliveryID(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	ctx := context.Background()
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true, bundleDeliveryID: "agent-7:d.1"}
	if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", opts); done {
		t.Fatalf("prepare ended the run: %v\n%s", err, out.String())
	}
	cleanupPreparedWindowsBundle(t, opts)
	// The ensure transaction installs the rendered config.
	rendered, err := os.ReadFile(opts.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigPath, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(ctx, layout.ConfigPath); err != nil {
		t.Fatalf("record installed bundle config: %v", err)
	}
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	expected := opts.bundle.prepared.Receipt.ExpectedDigest
	result.Policy = &enterprisestatus.PolicyState{EffectiveDigest: expected, GatewayReportedDigest: expected, ConfigGeneration: 3, Applied: true}
	finishWindowsEnterpriseBundle(cmd, opts, result)
	if len(result.Errors) != 0 || result.Bundle == nil || result.Bundle.State != enterprisebundle.StateConfirmed || result.Bundle.DeliveryID != "agent-7:d.1" {
		t.Fatalf("bundle not confirmed with its delivery id: errors %+v bundle %+v", result.Errors, result.Bundle)
	}

	// An elevated status reads the store the apply wrote.
	store := newWindowsBundleDriver(layout).Store
	bundleDevice(t, e)
	bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
	bundlePrivilege = func() error { return nil }
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{EffectiveDigest: expected, GatewayReportedDigest: expected, Applied: true}
	}
	status, code := runBundle(t, "status", "--json")
	doc := schemas.Validate(t, "bundle-status.schema.json", []byte(status))
	requireExit(t, doc, code, 0)
	for _, block := range []string{"current", "last_receipt", "bundle"} {
		if member, _ := doc[block].(map[string]any); member["delivery_id"] != "agent-7:d.1" {
			t.Fatalf("%s.delivery_id = %v, want agent-7:d.1: %s", block, member["delivery_id"], status)
		}
	}
	for _, file := range []string{filepath.Join(store.PublicReceiptEventsDir(), opts.bundle.prepared.Receipt.ReceiptID+".json"), store.PublicReceiptPath()} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if receipt := schemas.Validate(t, "bundle-receipt.schema.json", raw); receipt["delivery_id"] != "agent-7:d.1" {
			t.Fatalf("%s: %s", file, raw)
		}
	}
}

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
