// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1178: a failed hot apply whose restore of the previous config fails
// reports it and stops. Before, the restore error was ignored and the
// upgrade transaction ran with the config the attempt left behind as its
// preimage.
func TestWindowsEnterpriseHotConfigFailedRestoreStopsTheEnsure(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: HIGH\n"
	const next = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	host, opts := newHotConfigHost(t, previous, next)
	recorded := `{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`
	if err := os.WriteFile(configwrite.GenerationPath(host.configPath), []byte(recorded), 0o600); err != nil {
		t.Fatal(err)
	}
	apply := windowsEnterpriseHotConfigWrite
	windowsEnterpriseHotConfigWrite = func(ctx context.Context, path string, raw []byte, opt configwrite.Options) error {
		if strings.Contains(opt.Reason, "not applied") {
			return errors.New("config writer busy")
		}
		return apply(ctx, path, raw, opt)
	}
	// The gateway never adopts the change, so the attempt is undone.
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status")}}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`)
	var result enterprisestatus.Result
	if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil {
		t.Fatalf("decode result: %v: %s", jsonErr, stdout.String())
	}
	if len(stub.calls) != 1 {
		t.Fatalf("installer runs %q: want status only, no upgrade transaction after a failed restore", stub.calls)
	}
	if err == nil || result.OK || !windowsBundleHasCode(result.Errors, "config_restore_failed") {
		t.Fatalf("err=%v ok=%t errors=%+v, want config_restore_failed", err, result.OK, result.Errors)
	}
}

// GAP-1494: a failed hot apply that refreshed the enrolled targets for the
// new config publishes them again for the restored one.
func TestWindowsEnterpriseHotConfigUndoRepublishesTheTargets(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  block_at: MEDIUM\nenterprise:\n  enrollment:\n    include_users:\n      - alice\n      - bob\n"
	const next = "config_version: 9\nguardrail:\n  block_at: MEDIUM\nenterprise:\n  enrollment:\n    include_users:\n      - alice\n"
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	var refreshedWith []string
	windowsEnterpriseHotConfigRefreshTargets = func(context.Context, managed.StandaloneLayout) error {
		raw, err := os.ReadFile(host.configPath)
		if err != nil {
			return err
		}
		refreshedWith = append(refreshedWith, string(raw))
		return nil
	}
	failedVerify := installedStatus("Verify")
	failedVerify["ok"], failedVerify["gateway_ready"] = false, false
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), failedVerify, installedStatus("Upgrade")}}
	runHotConfigEnsure(t, host, opts, stub)
	if got, _ := os.ReadFile(host.configPath); string(got) != previous {
		t.Fatalf("config.yaml = %q, want the previous config back", got)
	}
	if len(refreshedWith) != 2 || refreshedWith[0] != next || refreshedWith[1] != previous {
		t.Fatalf("targets refreshed with %q, want the new config and then the restored one", refreshedWith)
	}
}

// GAP-1177: the unparseable-config rescue reads the installed config again
// under lifecycle.lock. A config another run committed while the preflight
// ran stays installed, and the stale broken bytes are not kept.
func TestWindowsEnterpriseUnparseableRescueKeepsAConcurrentCommit(t *testing.T) {
	const broken = "invalid: [\n"
	const committed = "config_version: 9\nguardrail:\n  block_at: HIGH\n"
	candidate := strings.Replace(standaloneGatewayCheckConfig, "config_version: 8\n", "config_version: 9\n", 1)
	originalLayout, originalSource := windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource
	t.Cleanup(func() {
		windowsEnterpriseStandaloneLayoutForPreflight = originalLayout
		windowsEnterpriseStandaloneConfigSource = originalSource
	})
	// No layout for the compile step: the rescue's own reads are what is tested.
	windowsEnterpriseStandaloneLayoutForPreflight = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{}, errors.New("no preflight layout in this test")
	}
	windowsEnterpriseStandaloneConfigSource = func(string) error { return nil }

	// Control: with no concurrent commit the supplied config replaces the
	// broken one, which is kept.
	host, opts := newHotConfigHost(t, broken, candidate)
	kept, err := installWindowsEnterpriseSuppliedConfigOverUnparseable(opts.configPath)
	if err != nil || kept == "" {
		t.Fatalf("rescue = (%q, %v), want the broken config kept", kept, err)
	}
	if got, _ := os.ReadFile(host.configPath); string(got) != candidate {
		t.Fatalf("config.yaml = %q, want the supplied config", got)
	}

	host, opts = newHotConfigHost(t, broken, candidate)
	windowsEnterpriseHotConfigLock = func(string) (func(), error) {
		// Another lifecycle run commits a valid config before this one gets the lock.
		if err := os.WriteFile(host.configPath, []byte(committed), 0o600); err != nil {
			return nil, err
		}
		return func() {}, nil
	}
	kept, err = installWindowsEnterpriseSuppliedConfigOverUnparseable(opts.configPath)
	if err != nil || kept != "" {
		t.Fatalf("rescue = (%q, %v), want nothing to do after the concurrent commit", kept, err)
	}
	if got, _ := os.ReadFile(host.configPath); string(got) != committed {
		t.Fatalf("config.yaml = %q, want the concurrently committed config", got)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(host.configPath), "rejected-config.yaml")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rejected-config.yaml written from stale bytes: %v", statErr)
	}
}
