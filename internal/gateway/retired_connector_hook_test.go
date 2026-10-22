// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// until 1.1: the retired OpenHands and OmniGent hook routes
// (retired_connector_hook.go). Delete with that file.

var retiredHookPaths = []string{"/api/v1/openhands/hook", "/api/v1/omnigent/hook"}

// requireRetiredBlock checks the answer is the block verdict both older
// clients read: action block (the OmniGent module and the OpenHands hook)
// and a deny hook_output (the OpenHands hook's Secure Client render), with
// the removal reason.
func requireRetiredBlock(t *testing.T, what string, response *httptest.ResponseRecorder) {
	t.Helper()
	requireRetiredBlockBody(t, what, response.Code, response.Body.Bytes())
}

func requireRetiredBlockBody(t *testing.T, what string, status int, body []byte) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("%s: status %d (%s); an older hook in fail mode open allows on any status but 2xx", what, status, body)
	}
	var verdict struct {
		Action     string `json:"action"`
		Reason     string `json:"reason"`
		HookOutput struct {
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		} `json:"hook_output"`
	}
	if err := json.Unmarshal(body, &verdict); err != nil {
		t.Fatalf("%s: body %q: %v", what, body, err)
	}
	if verdict.Action != "block" || verdict.HookOutput.Decision != "deny" ||
		!strings.Contains(verdict.Reason, "support was removed in DefenseClaw 1.0.4") || verdict.HookOutput.Reason != verdict.Reason {
		t.Fatalf("%s: verdict %+v, want a block with the removal reason", what, verdict)
	}
}

// retiredHookCall is one way an old hook, or anything else, calls a retired
// route: every credential state and caller.
type retiredHookCall struct {
	name, method, remote, header, value string
}

func retiredHookCalls(master string) []retiredHookCall {
	return []retiredHookCall{
		{"no token", http.MethodPost, "127.0.0.1:40000", "", ""},
		{"the revoked token", http.MethodPost, "127.0.0.1:40000", "Authorization", "Bearer " + strings.Repeat("a", 64)},
		{"a valid token", http.MethodPost, "127.0.0.1:40000", "Authorization", "Bearer " + master},
		{"a valid token in X-DC-Auth", http.MethodPost, "127.0.0.1:40000", "X-DC-Auth", master},
		{"a sandbox credential", http.MethodPost, "127.0.0.1:40000", "Authorization", "Bearer dcsb_" + strings.Repeat("b", 43)},
		{"a malformed header", http.MethodPost, "127.0.0.1:40000", "Authorization", "Basic Zm9vOmJhcg=="},
		{"GET", http.MethodGet, "127.0.0.1:40000", "", ""},
		{"ipv6 loopback", http.MethodPost, "[::1]:40000", "", ""},
		{"another address", http.MethodPost, "10.0.0.5:40000", "", ""},
	}
}

func (c retiredHookCall) request(path string) *http.Request {
	request := httptest.NewRequest(c.method, path, strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"bash"}`))
	request.RemoteAddr = c.remote
	request.Header.Set("Content-Type", "application/json")
	if c.header != "" {
		request.Header.Set(c.header, c.value)
	}
	return request
}

// Safety net: an OmniGent process that imported the 1.0.3 policy module
// before the upgrade, or an OpenHands hook the teardown could not reach,
// still posts to its old route. The gateway answers with a block before any
// credential check: with no token, the revoked one, a valid one, a sandbox
// credential, from any address, never the 401 an old hook in fail mode
// open turns into an allow. Other routes keep their authentication.
func TestRetiredConnectorHookRoutesBlockOverTCP(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	api.scannerCfg = &config.Config{}
	api.scannerCfg.Gateway.Token = "master-token"
	reached := false
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		http.NotFound(w, r)
	}))
	for _, path := range retiredHookPaths {
		for _, call := range retiredHookCalls("master-token") {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, call.request(path))
			requireRetiredBlock(t, path+" with "+call.name, response)
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

// postRetired posts body to url and returns the answer; the server must keep
// the connection (no Connection: close), so the client reads the block and
// never a reset.
func postRetired(t *testing.T, client *http.Client, url string, body []byte) (int, []byte) {
	t.Helper()
	response, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s with %d bytes: %v", url, len(body), err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the answer to %s: %v", url, err)
	}
	if response.Close {
		t.Fatalf("POST %s with %d bytes: the server closed the connection after the answer", url, len(body))
	}
	return response.StatusCode, data
}

// A large hook body (the old hooks send up to 1 MiB) gets the block on a
// connection the server keeps: answering with most of the body unread made
// the server close the connection, and a client still sending sees a reset.
func TestRetiredConnectorHookRoutesKeepTheConnectionForTheBlock(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	api.scannerCfg = &config.Config{}
	api.scannerCfg.Gateway.Token = "master-token"
	server := httptest.NewServer(api.tokenAuth(http.NotFoundHandler()))
	t.Cleanup(server.Close)
	client := server.Client()
	large := append([]byte(`{"tool_input":"`), bytes.Repeat([]byte("x"), 2<<20)...)
	large = append(large, `"}`...)
	for _, path := range retiredHookPaths {
		for _, body := range [][]byte{[]byte(`{}`), large} {
			status, data := postRetired(t, client, server.URL+path, body)
			requireRetiredBlockBody(t, path, status, data)
		}
	}
}
