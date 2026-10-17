// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// contractUnixEnv points the Linux and macOS lifecycle at an empty device
// tree that a root caller runs against, with no host commands.
func contractUnixEnv(t *testing.T) (root string, layout managed.StandaloneLayout) {
	t.Helper()
	goos := enterpriseunix.CurrentGOOS()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Skip(err)
	}
	root = t.TempDir()
	previous := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 0 }, Runner: noHostCommands{}}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })
	return root, layout
}

func contractUnixPlatform() string {
	if enterpriseunix.CurrentGOOS() == "darwin" {
		return "macos"
	}
	return "linux"
}

// TestManagementContractUnixStatusAndSecrets validates `enterprise <os>
// status`, `enterprise secret status` and `enterprise secret set` as a root
// caller prints them on a device that is not installed yet (contract 5.0).
func TestManagementContractUnixStatusAndSecrets(t *testing.T) {
	schemas := compileManagementContract(t)
	root, layout := contractUnixEnv(t)

	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := runUnixLifecycle(cmd, contractUnixPlatform(), "status", &unixLifecycleOptions{json: true})
	doc := schemas.validate(t, "lifecycle-result.schema.json", out.Bytes())
	requireExit(t, doc, commandExitCode(err), commandExitCode(err))
	if doc["installed"] != false {
		t.Fatalf("status of an empty device = %s", out.String())
	}

	const value = "contract-test-credential-value"
	set := newEnterpriseSecretCommand("set", "")
	set.SetContext(t.Context())
	out.Reset()
	set.SetOut(&out)
	set.SetIn(strings.NewReader(value + "\n"))
	err = runEnterpriseSecret(set, "set", &enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true})
	if strings.Contains(out.String(), value) {
		t.Fatalf("the credential value was printed: %s", out.String())
	}
	doc = schemas.validate(t, "secret-result.schema.json", out.Bytes())
	requireExit(t, doc, commandExitCode(err), commandExitCode(err))

	secrets := root + layout.SecretsDir
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "splunk-hec-token"), []byte("contract-status-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := newEnterpriseSecretCommand("status", "")
	out.Reset()
	status.SetOut(&out)
	if err := runEnterpriseSecret(status, "status", &enterpriseSecretOptions{json: true}); err != nil {
		t.Fatalf("secret status: %v", err)
	}
	if strings.Contains(out.String(), "contract-status-value") {
		t.Fatalf("secret status printed a value: %s", out.String())
	}
	schemas.validate(t, "secret-result.schema.json", out.Bytes())
}

// TestManagementContractAnchorsInstallRefusals validates the refusals of
// `enterprise bundle anchors install` before it reads the source.
func TestManagementContractAnchorsInstallRefusals(t *testing.T) {
	schemas := compileManagementContract(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	for name, setup := range map[string]func(){
		"not managed":   func() { bundleManagedDevice = func() bool { return false } },
		"secure client": func() { bundleSecureClient = func() bool { return true } },
	} {
		t.Run(name, func(t *testing.T) {
			savedDevice, savedSC := bundleManagedDevice, bundleSecureClient
			t.Cleanup(func() { bundleManagedDevice, bundleSecureClient = savedDevice, savedSC })
			setup()
			out, code := runBundle(t, "anchors", "install", "--file", e.anchors, "--json")
			doc := schemas.validate(t, "anchors-install.schema.json", []byte(out))
			requireExit(t, doc, code, bundleFailureExitCode())
		})
	}
}

// TestManagementContractAnchorsInstallResults validates every result of
// `enterprise bundle anchors install` on a managed device: installed,
// unchanged, replaced, and the refusals an agent acts on (insecure or
// invalid source, usage, busy, not root).
func TestManagementContractAnchorsInstallResults(t *testing.T) {
	schemas := compileManagementContract(t)
	root, layout, euid := anchorsInstallDevice(t)
	install := func(want int, args ...string) map[string]any {
		t.Helper()
		out, code := runBundle(t, append([]string{"anchors", "install"}, args...)...)
		doc := schemas.validate(t, "anchors-install.schema.json", []byte(out))
		requireExit(t, doc, code, want)
		return doc
	}
	errorCode := func(doc map[string]any) any {
		errs, _ := doc["errors"].([]any)
		if len(errs) == 0 {
			return nil
		}
		return errs[0].(map[string]any)["code"]
	}
	first := testAnchorsFile(t, "active", "retired")
	if doc := install(0, "--file", first, "--json"); doc["result"] != "installed" {
		t.Fatalf("first install: %v", doc)
	}
	if doc := install(0, "--file", first, "--json"); doc["result"] != "unchanged" {
		t.Fatalf("same file again: %v", doc)
	}
	if doc := install(0, "--file", testAnchorsFile(t, "active", "revoked"), "--json"); doc["result"] != "replaced" || doc["previous_sha256"] == nil {
		t.Fatalf("other file: %v", doc)
	}

	invalid := filepath.Join(t.TempDir(), "bundle-anchors.json")
	if err := os.WriteFile(invalid, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if doc := install(1, "--file", invalid, "--json"); errorCode(doc) != "anchor_invalid" {
		t.Fatalf("invalid source: %v", doc)
	}

	insecure := testAnchorsFile(t, "active")
	trusting := newUnixLifecycleEnv
	t.Cleanup(func() { newUnixLifecycleEnv = trusting })
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		env, err := trusting(goos)
		if err == nil {
			env.Trust = func(path string, _ enterpriseunix.TrustKind) error {
				if path == insecure {
					return errors.New("the file is writable by group staff")
				}
				return nil
			}
		}
		return env, err
	}
	if doc := install(1, "--file", insecure, "--json"); errorCode(doc) != "anchor_insecure" {
		t.Fatalf("insecure source: %v", doc)
	}
	newUnixLifecycleEnv = trusting

	install(2, "--json")
	install(2, "--file", first, "--lock-wait", "1h", "--json")

	lock, err := os.OpenFile(filepath.Join(root, layout.LifecycleDir, "lifecycle.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if doc := install(75, "--file", first, "--lock-wait", "1s", "--json"); errorCode(doc) != "lifecycle_busy" {
		t.Fatalf("busy: %v", doc)
	}
	_ = lock.Close()

	*euid = 1000
	if doc := install(1, "--file", first, "--json"); errorCode(doc) != "not_root" {
		t.Fatalf("not root: %v", doc)
	}
}
