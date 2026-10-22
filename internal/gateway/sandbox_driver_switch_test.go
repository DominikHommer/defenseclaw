// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func TestSandboxResolveDriverMismatchIsTemporary(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.cfg.Enterprise.OpenShell.Driver = "docker"
	req := claudeResolve()
	req.Driver, req.DriverReason = "vm", "configured"
	rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, req, nil)
	var out sandboxrelay.ResolveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusServiceUnavailable || out.Refusal == nil || out.Refusal.Reason != sandboxrelay.DetailSetupChanging ||
		!strings.Contains(out.Refusal.Message, "defenseclaw sandbox stop NAME") || out.Registration.ID != "" {
		t.Fatalf("driver change refusal: %d %s", rec.Code, rec.Body.String())
	}
}
