// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

func syntheticNativeProfile(connector string) *NativeSandboxProfile {
	contract := connector + "-contract-test"
	if connector == "codex" {
		contract = "codex-hooks-v4"
	}
	return &NativeSandboxProfile{Version: 1, SessionID: strings.Repeat("a", 32), Connector: connector, HookContract: contract}
}

func TestNativeSandboxProfileRefusesAmbiguousOrCredentialBearingData(t *testing.T) {
	raw, err := json.Marshal(syntheticNativeProfile("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	if profile, err := DecodeNativeSandboxProfile(raw); err != nil || profile.Validate() != nil {
		t.Fatal("inert fixed profile refused")
	}
	for _, body := range []string{
		string(raw[:len(raw)-1]) + `,"token":"forbidden"}`,
		string(raw[:len(raw)-1]) + `,"connector":"codex"}`,
		string(raw) + `{}`,
		strings.Replace(string(raw), `"version":1`, `"version":"1"`, 1),
		strings.Replace(string(raw), `"hook_surface":""`, `"hook_surface":null`, 1),
		strings.Replace(string(raw), `"claudecode"`, `"unknown"`, 1),
		strings.Repeat(" ", 4097),
	} {
		if _, err := DecodeNativeSandboxProfile([]byte(body)); err == nil {
			t.Fatal("ambiguous native profile was accepted")
		}
	}
}

func TestNativeSandboxAllExistingConnectorExchangesAvoidUserStateAndBearer(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "must-not-leave-test")
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "attacker.invalid:1234")
	for _, name := range []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "omnigent", "opencode", "openhands"} {
		t.Run(name, func(t *testing.T) {
			profile := syntheticNativeProfile(name)
			event := "PreToolUse"
			switch name {
			case "copilot":
				event = "preToolUse"
			case "amp":
				event = "tool.call"
			case "opencode":
				event = "tool.execute.before"
			case "cursor":
				event = "beforeShellExecution"
			}
			var stdout, stderr bytes.Buffer
			transport := &stubRT{status: 200, body: `{"action":"allow"}`}
			opts := Options{Connector: name, Event: event, NativeSandbox: profile,
				HookContractID: profile.HookContract, HookSurface: profile.HookSurface,
				Home: "deliberately-missing-user-state", HookDir: "must-not-read-sidecars",
				Stdin: strings.NewReader(`{"hook_event_name":"PreToolUse"}`), Stdout: &stdout, Stderr: &stderr,
				HTTPClient: &http.Client{Transport: transport}, FailMode: "open"}
			if code := Run(context.Background(), opts); code != 0 || transport.requests != 1 {
				t.Fatalf("native exchange failed: code=%d requests=%d", code, transport.requests)
			}
			if transport.gotReq.URL.Host != "defenseclaw-native.invalid" || transport.gotReq.Header.Get("Authorization") != "" ||
				transport.gotReq.Header.Get("X-DefenseClaw-Hook-Idempotency-Key") == "" {
				t.Fatal("native exchange selected user credentials or another transport")
			}
			if name == "codex" && transport.gotReq.Header.Get("X-DefenseClaw-Hook-Event") != event {
				t.Fatal("existing Codex event binding was lost")
			}
			if name == "omnigent" && strings.TrimSpace(stdout.String()) != `{"action":"allow"}` {
				t.Fatal("OmniGent raw gateway response was given a new command-hook dialect")
			}
		})
	}
}

func TestNativeSandboxMixedAuthorityAndInvalidProfileRefuseBeforeRequest(t *testing.T) {
	for _, mutation := range []string{"profile", "connector", "contract", "token", "managed", "recovery"} {
		t.Run(mutation, func(t *testing.T) {
			profile := syntheticNativeProfile("claudecode")
			transport := &stubRT{status: 200, body: `{"action":"allow"}`}
			var output bytes.Buffer
			opts := Options{Connector: "claudecode", NativeSandbox: profile, HookContractID: profile.HookContract,
				HTTPClient: &http.Client{Transport: transport}, Stdout: &output, Stderr: &output}
			switch mutation {
			case "profile":
				opts.NativeSandbox = &NativeSandboxProfile{}
			case "connector":
				profile.Connector = "codex"
			case "contract":
				opts.HookContractID = "another-contract"
			case "token":
				opts.Token = "forbidden"
			case "managed":
				opts.ManagedEnterprise = true
			case "recovery":
				opts.GatewayRecovery = func(context.Context, error) error { t.Fatal("recovery reached"); return nil }
			}
			if Run(context.Background(), opts) == 0 || transport.requests != 0 {
				t.Fatal("invalid native authority reached a request")
			}
		})
	}
}

func TestNativeSandboxNotifyDoesNotReachTokenTransport(t *testing.T) {
	transport := &stubRT{status: 200, body: `{}`}
	opts := Options{NativeSandbox: syntheticNativeProfile("codex"), HTTPClient: &http.Client{Transport: transport}}
	if RunCodexNotify(context.Background(), opts, []byte(`{}`)) == 0 || transport.requests != 0 {
		t.Fatal("unadmitted notify reached transport")
	}
}

func TestNativeSandboxTransportRefusesAlternativeDialAndRedirectWithoutContact(t *testing.T) {
	client, err := nativeSandboxHTTPClient(time.Second)
	if runtime.GOOS != "linux" {
		if err == nil || client != nil {
			t.Fatal("Linux native transport became available on another platform")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableKeepAlives || !transport.DisableCompression {
		t.Fatal("native transport inherited ambient HTTP configuration")
	}
	for _, route := range [][2]string{{"tcp", "another.invalid:80"}, {"unix", "defenseclaw-native.invalid:80"}} {
		if connection, err := transport.DialContext(context.Background(), route[0], route[1]); err == nil || connection != nil {
			t.Fatal("alternative dial route was accepted")
		}
	}
	if client.CheckRedirect(new(http.Request), nil) != http.ErrUseLastResponse {
		t.Fatal("native transport followed a redirect")
	}
}

func TestNativeSandboxOversizedResponsesCannotPassAsValidPrefixes(t *testing.T) {
	for _, connector := range []string{"claudecode", "omnigent"} {
		profile := syntheticNativeProfile(connector)
		transport := &stubRT{status: 200, body: `{"action":"allow"}` + strings.Repeat(" ", int(defaultMaxBody))}
		var stdout, stderr bytes.Buffer
		opts := Options{Connector: connector, Event: "PreToolUse", NativeSandbox: profile, HookContractID: profile.HookContract,
			HTTPClient: &http.Client{Transport: transport}, Stdin: strings.NewReader(`{}`), Stdout: &stdout, Stderr: &stderr}
		if Run(context.Background(), opts) == 0 || stdout.Len() != 0 || transport.requests != 1 {
			t.Fatal("an oversized response's valid prefix became an allow")
		}
	}
}
