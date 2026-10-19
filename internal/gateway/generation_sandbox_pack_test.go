// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0229: on a managed computer a required sandbox pack that does not
// load fails the generation, so the gateway refuses to start on it, a
// reload keeps the last good generation, and `policy digest` (which builds
// the same generation) refuses it before ensure would restart the gateway.
// The same pack on an unmanaged computer is left to the sandbox routes.
func TestBuildGenerationRefusesARequiredSandboxPackThatDoesNotLoad(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "corp", "pack.yaml")
	if err := os.MkdirAll(filepath.Dir(pack), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pack, []byte("version: 1\nname: corp\nnetwork:\n  mode: unbuildable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	cfg.OpenShell.PackDir = dir
	cfg.OpenShell.Admin.RequiredPack = pack
	if _, err := buildGeneration(context.Background(), generationInputs{cfg: cfg}); err == nil ||
		!strings.Contains(err.Error(), "sandbox pack "+pack+" does not load") {
		t.Fatalf("buildGeneration error = %v, want the sandbox pack refused", err)
	}
	if _, err := ComputeEffectivePolicy(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Fatalf("ComputeEffectivePolicy error = %v, want the sandbox pack refused", err)
	}

	// A profile's own required pack is checked too.
	cfg.OpenShell.Admin.RequiredPack = ""
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Sandbox: &config.OpenShellAdminConfig{RequiredPack: pack}}}
	if _, err := buildGeneration(context.Background(), generationInputs{cfg: cfg}); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Fatalf("buildGeneration error = %v, want the profile's sandbox pack refused", err)
	}

	cfg.DeploymentMode = ""
	if _, err := buildGeneration(context.Background(), generationInputs{cfg: cfg}); err != nil {
		t.Fatalf("an unmanaged generation: %v", err)
	}
}
