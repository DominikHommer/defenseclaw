// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

// until 1.1: the retired OpenHands and OmniGent hook routes
// (retired_connector_hook.go). Delete with that file.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// requireRetiredBlock checks the answer is the block verdict both older
// clients read: action block (the OmniGent module and the OpenHands hook)
// and a deny hook_output (the OpenHands hook's Secure Client render), with
// the removal reason.
func requireRetiredBlock(t *testing.T, what string, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("%s: status %d (%s); an older hook in fail mode open allows on any status but 2xx", what, response.Code, response.Body.String())
	}
	var verdict struct {
		Action     string `json:"action"`
		Reason     string `json:"reason"`
		HookOutput struct {
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		} `json:"hook_output"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &verdict); err != nil {
		t.Fatalf("%s: body %q: %v", what, response.Body.String(), err)
	}
	if verdict.Action != "block" || verdict.HookOutput.Decision != "deny" ||
		!strings.Contains(verdict.Reason, "support was removed in DefenseClaw 1.0.4") || verdict.HookOutput.Reason != verdict.Reason {
		t.Fatalf("%s: verdict %+v, want a block with the removal reason", what, verdict)
	}
}

// An OmniGent process that imported the 1.0.3 policy module before the
// upgrade, or an OpenHands hook the teardown could not reach, still posts to
// its old route. The gateway answers with a block, with no token (the
// teardown revoked it) and from any address, never a 404 or 401 that the old
// hook in fail mode open turns into an allow. Other routes keep their
// authentication.
func TestRetiredConnectorHookRoutesBlockOverTCP(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	api.scannerCfg = &config.Config{}
	api.scannerCfg.Gateway.Token = "master-token"
	reached := false
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		http.NotFound(w, r)
	}))
	for _, path := range []string{"/api/v1/openhands/hook", "/api/v1/omnigent/hook"} {
		for _, tc := range []struct{ name, remote, token string }{
			{"loopback, no token", "127.0.0.1:40000", ""},
			{"loopback, the revoked token", "127.0.0.1:40000", strings.Repeat("a", 64)},
			{"ipv6 loopback", "[::1]:40000", ""},
			{"another address", "10.0.0.5:40000", ""},
		} {
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"bash"}`))
			request.RemoteAddr = tc.remote
			request.Header.Set("Content-Type", "application/json")
			if tc.token != "" {
				request.Header.Set("Authorization", "Bearer "+tc.token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			requireRetiredBlock(t, path+" "+tc.name, response)
		}
	}
	if reached {
		t.Fatal("a retired hook request reached the routes behind authentication")
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(`{}`))
	request.RemoteAddr = "127.0.0.1:40000"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || reached {
		t.Fatalf("codex hook without a token: status %d, reached %v; want 401", response.Code, reached)
	}
}

// On a managed Unix host the 1.0.3 OmniGent module posts over the hook
// socket with no token. A verified peer gets the block; an unverified one is
// still refused before any route.
func TestRetiredConnectorHookRoutesBlockOverTheHookSocket(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	handler := api.managedHookPeerAuth(newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil), api.managedHookSocketMux())
	for _, path := range []string{"/api/v1/openhands/hook", "/api/v1/omnigent/hook"} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"phase":"pre_tool"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "omnigent-policy/1.0")
		request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{UID: 1001, Name: "alice"}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		requireRetiredBlock(t, path+" over the hook socket", response)

		unverified := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, unverified)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s from an unverified peer: status %d, want 403", path, response.Code)
		}
	}
}
