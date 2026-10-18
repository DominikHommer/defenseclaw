// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// An administrator signs a settings-only bundle made from a shipped managed
// template plus one tested change on a workstation that has no DefenseClaw
// install. The template sets policy_dir to the administrator folder, whose
// missing default pack falls back to the vendor folder, so the signer must
// load the shipped packs this binary embeds instead of its own /opt tree,
// and its digest must equal the one the device computes for the installed
// config (GAP-0223). The test runs on every CI host OS, so a Windows, macOS
// and Linux signer are all covered.
func TestOfflineSignShippedTemplateMatchesDeviceDigest(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(file), "..", "..")
	for _, tc := range []struct{ goos, template string }{
		{"linux", "linux-standalone.yaml"},
		{"darwin", "macos-standalone.yaml"},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			layout, err := managed.StandaloneLayoutFor(tc.goos)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path.Join(layout.PolicyDir, "guardrail", "default")); err == nil {
				t.Skipf("this host has the device pack folder %s/guardrail/default", layout.PolicyDir)
			}
			template, err := os.ReadFile(filepath.Join(repo, "testdata", "enterprise-configs", tc.template))
			if err != nil {
				t.Fatal(err)
			}
			const anchor = "guardrail:\n  enabled: true\n"
			if !strings.Contains(string(template), anchor) {
				t.Fatalf("%s has no %q", tc.template, anchor)
			}
			source := strings.Replace(string(template), anchor, anchor+"  block_at: MEDIUM\n", 1)
			b := &enterprisebundle.Bundle{Files: map[string][]byte{enterprisebundle.ConfigName: []byte(source)}}

			// Signer: the bundle sign digest, with its working copy as the
			// bundle root.
			signerRoot := t.TempDir()
			digester := func(ctx context.Context, cfg *config.Config, raw []byte, goos, root string) (string, error) {
				policy, err := ComputeEffectivePolicyFor(ctx, cfg, EffectivePolicyOptions{GOOS: goos, BundleRoot: root, Raw: raw})
				return policy.Digest, err
			}
			signed, err := enterprisebundle.EffectivePolicyDigests(context.Background(), b, signerRoot, []string{tc.goos}, digester)
			if err != nil {
				t.Fatalf("sign %s from %s: %v", tc.goos, tc.template, err)
			}

			// Device: apply renders config.yaml for its receipt directory and
			// the gateway loads it from the layout config path. The device's
			// installed vendor tree is a copy of the source release policies.
			const bundleID, receiptID = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z2A", "r-01J9ZK3Q4R5S6T7V8W9X0Y1Z2B"
			bundles := path.Join(layout.ConfigDir, enterprisebundle.BundlesDirName)
			installed, err := enterprisebundle.RenderConfig(b, path.Join(bundles, enterprisebundle.VersionDirNameForReceipt(10324003, bundleID, receiptID)))
			if err != nil {
				t.Fatal(err)
			}
			deviceCfg, err := config.LoadRuntimeV8InspectionCandidateForLayout(layout.ConfigPath, installed, layout.DataDir, tc.goos)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := deviceCfg.ResolveRulePackDir(globalRulePackRef(deviceCfg)), path.Join(layout.VendorPolicyDir, "guardrail", "default"); got != want {
				t.Fatalf("device default pack %q, want the vendor fallback %q", got, want)
			}
			installedVendor := t.TempDir()
			if err := os.CopyFS(installedVendor, os.DirFS(filepath.Join(repo, "policies"))); err != nil {
				t.Fatal(err)
			}
			packCfg := cloneConfig(deviceCfg)
			packCfg.UseOfflineVendorPolicies(layout.VendorPolicyDir, installedVendor)
			rulePacks, err := generationRulePacks(packCfg)
			if err != nil {
				t.Fatal(err)
			}
			profiles, err := newGuardrailProfileSet(packCfg, rulePacks.cache, false)
			if err != nil {
				profiles = nil
			}
			// The generation record names the bundle and the settings-only
			// config names no bundle file, so the gateway digests in the
			// bundle scope of the version directory (GAP-0158).
			device, err := buildGeneration(context.Background(), generationInputs{cfg: deviceCfg, raw: installed,
				rulePacks: rulePacks, profiles: profiles, goos: tc.goos,
				bundleRoot:   path.Join(bundles, enterprisebundle.VersionDirName(10324003, bundleID)),
				vendorRoot:   installedVendor,
				vendorTarget: layout.VendorPolicyDir})
			if err != nil {
				t.Fatal(err)
			}
			if device.Digest != signed[tc.goos] {
				t.Fatalf("device digest %s != signed %s; device components %v", device.Digest, signed[tc.goos], device.Components)
			}
		})
	}
}
