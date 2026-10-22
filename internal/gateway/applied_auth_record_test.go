// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A per-user gateway records the token_env and inline token of the config
// it loaded, for `provenance show` to authenticate with after config.yaml
// was edited into a state the gateway rejected. A standalone deployment
// records nothing: its lifecycle keeps the config it applied.
func TestRecordAppliedGatewayAuthKeepsTheLoadedCredentialConfiguration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(daemon.EnvDaemon, "1")
	t.Setenv(daemon.EnvDataDir, dir)
	cfg := config.DefaultConfig()
	cfg.DataDir = dir
	cfg.Gateway.TokenEnv = "R104_CUSTOM_TOKEN"
	cfg.Gateway.Token = "inline token"
	s := &Sidecar{cfg: cfg}
	s.recordAppliedGatewayAuth(cfg.Gateway)
	got, ok := daemon.New(dir).AppliedAuth(os.Getpid())
	if want := (daemon.AppliedAuth{TokenEnv: "R104_CUSTOM_TOKEN", Token: "inline token"}); !ok || got != want {
		t.Fatalf("applied auth = %+v, %v; want %+v", got, ok, want)
	}

	standalone := t.TempDir()
	t.Setenv(daemon.EnvDataDir, standalone)
	managedCfg := config.DefaultConfig()
	managedCfg.DataDir = standalone
	managedCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	managedCfg.Enterprise.Profile = managed.ProfileStandalone
	managedCfg.Gateway.Token = "inline token"
	(&Sidecar{cfg: managedCfg}).recordAppliedGatewayAuth(managedCfg.Gateway)
	if _, err := os.Lstat(filepath.Join(standalone, daemon.AppliedAuthFileName)); !os.IsNotExist(err) {
		t.Fatalf("a standalone gateway wrote the per-user auth record: %v", err)
	}
}
