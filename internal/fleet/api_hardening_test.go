// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
)

// hardeningAPI builds an API over a SQLite store at dbPath (a fresh one when
// dbPath is empty) so tests can simulate a gateway restart on the same state.
func hardeningAPI(t *testing.T, settings FleetSettings, dbPath string) (*API, *SQLiteStore, *manager.FleetManager, string) {
	t.Helper()
	t.Setenv("DCLAW_FLEET_API_TOKEN", "")
	t.Setenv("DCLAW_FLEET_TENANT_TOKENS", "")
	if dbPath == "" {
		dbPath = filepath.Join(securitySQLiteDir(t), "devices.db")
	}
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	mgr := manager.New(nil)
	mgr.SetStore(store)
	if _, err := mgr.LoadFromStore(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	api := NewAPI(ctx, mgr, securityTestCache(), WithDeviceKeyStore(store), WithDecommissionStore(store),
		WithAuditEmitter(&passingCredentialAudit{}), WithFleetSettings(settings))
	return api, store, mgr, dbPath
}

func registerDeviceVia(t *testing.T, api *API, token string, tenant, fleetID uint16, dev uint32, extra string, tlsOn bool) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"tenant_id":%d,"fleet_id":%d,"device_id":%d%s}`, tenant, fleetID, dev, extra)
	rec := securityTestRequest(api, http.MethodPost, "/devices", token, body, tlsOn)
	var out struct {
		DeviceKey string `json:"device_key"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out.DeviceKey
}

func healthCode(api *API, token string) int {
	return securityTestRequest(api, http.MethodGet, "/health", token, "", true).Code
}

// A rotated admin token survives a gateway restart: the rotated-out token is
// not revived and the rotated token keeps working.
func TestAdminTokenRotationSurvivesRestart(t *testing.T) {
	settings := FleetSettings{APIToken: "original-admin-token"}
	api, _, _, dbPath := hardeningAPI(t, settings, "")
	rec := securityTestRequest(api, http.MethodPost, "/token/rotate", "original-admin-token", "{}", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if healthCode(api, "original-admin-token") != http.StatusUnauthorized || healthCode(api, out.Token) != http.StatusOK {
		t.Fatal("in-process rotation did not take effect")
	}

	restarted, _, _, _ := hardeningAPI(t, settings, dbPath)
	if c := healthCode(restarted, "original-admin-token"); c != http.StatusUnauthorized {
		t.Fatalf("rotated-out token valid again after restart: %d", c)
	}
	if c := healthCode(restarted, out.Token); c != http.StatusOK {
		t.Fatalf("rotated token rejected after restart: %d", c)
	}

	// Saving the rotated token in the secret source keeps it working.
	saved, _, _, _ := hardeningAPI(t, FleetSettings{APIToken: out.Token}, dbPath)
	if healthCode(saved, out.Token) != http.StatusOK || healthCode(saved, "original-admin-token") != http.StatusUnauthorized {
		t.Fatal("configuring the rotated token changed which token is accepted")
	}

	// An operator who configures a brand-new secret replaces the rotation.
	fresh, _, _, _ := hardeningAPI(t, FleetSettings{APIToken: "operator-new-secret"}, dbPath)
	if healthCode(fresh, "operator-new-secret") != http.StatusOK {
		t.Fatal("newly configured admin token rejected")
	}
	if healthCode(fresh, out.Token) != http.StatusUnauthorized || healthCode(fresh, "original-admin-token") != http.StatusUnauthorized {
		t.Fatal("superseded tokens still accepted after configuring a new secret")
	}
}

// Rotation is refused when it cannot be persisted.
func TestAdminTokenRotationRequiresDurableStore(t *testing.T) {
	t.Setenv("DCLAW_FLEET_API_TOKEN", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	api := NewAPI(ctx, manager.New(nil), securityTestCache(), WithAuditEmitter(&passingCredentialAudit{}),
		WithFleetSettings(FleetSettings{APIToken: "admin"}))
	rec := securityTestRequest(api, http.MethodPost, "/token/rotate", "admin", "{}", true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("rotation without durable store: %d %s", rec.Code, rec.Body.String())
	}
	if healthCode(api, "admin") != http.StatusOK {
		t.Fatal("refused rotation changed the admin token")
	}
}
