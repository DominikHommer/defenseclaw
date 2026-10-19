// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const NativeSandboxHookDirectory = "/run/defenseclaw-hook"
const NativeSandboxHookSocket = NativeSandboxHookDirectory + "/ingress.sock"
const NativeSandboxHookProfile = NativeSandboxHookDirectory + "/runtime.json"
const nativeSandboxHookOrigin = "http://defenseclaw-native.invalid"

var errNativeSandboxHook = errors.New("native sandbox hook runtime unavailable")

// NativeSandboxProfile describes the Linux session transport selected by the
// trusted factory. It contains no credential or endpoint selector. The caller
// must read it from the admitted readonly held directory, never user state.
// Validation here is a schema check, not proof of native hook qualification.
type NativeSandboxProfile struct {
	Version      int    `json:"version"`
	SessionID    string `json:"session_id"`
	Connector    string `json:"connector"`
	HookContract string `json:"hook_contract"`
	HookSurface  string `json:"hook_surface"`
}

func nativeRuntimeAtom(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !(value[0] >= 'a' && value[0] <= 'z' || value[0] >= 'A' && value[0] <= 'Z' || value[0] >= '0' && value[0] <= '9') {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:-", c)) {
			return false
		}
	}
	return true
}

func (profile NativeSandboxProfile) Validate() error {
	_, listed := specFor(profile.Connector)
	if profile.Version != 1 || !nativeRuntimeAtom(profile.SessionID, 128) ||
		!nativeRuntimeAtom(profile.HookContract, 128) || (!listed && profile.Connector != "omnigent") ||
		profile.Connector != strings.ToLower(strings.TrimSpace(profile.Connector)) ||
		profile.HookSurface != "" && !HookSurfaceAllowed(profile.Connector, profile.HookSurface) {
		return errNativeSandboxHook
	}
	return nil
}

// DecodeNativeSandboxProfile refuses duplicate/unknown keys and trailing data.
// The filesystem trust checks belong to the Linux CLI resolver.
func DecodeNativeSandboxProfile(raw []byte) (*NativeSandboxProfile, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, errNativeSandboxHook
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errNativeSandboxHook
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || fields[name] != nil ||
			name != "version" && name != "session_id" && name != "connector" && name != "hook_contract" && name != "hook_surface" {
			return nil, errNativeSandboxHook
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, errNativeSandboxHook
		}
		if name != "version" && (len(bytes.TrimSpace(value)) == 0 || bytes.TrimSpace(value)[0] != '"') {
			return nil, errNativeSandboxHook
		}
		fields[name] = value
	}
	end, err := decoder.Token()
	var extra any
	if err != nil || end != json.Delim('}') || decoder.Decode(&extra) != io.EOF || len(fields) != 5 {
		return nil, errNativeSandboxHook
	}
	var profile NativeSandboxProfile
	if json.Unmarshal(fields["version"], &profile.Version) != nil || json.Unmarshal(fields["session_id"], &profile.SessionID) != nil ||
		json.Unmarshal(fields["connector"], &profile.Connector) != nil || json.Unmarshal(fields["hook_contract"], &profile.HookContract) != nil ||
		json.Unmarshal(fields["hook_surface"], &profile.HookSurface) != nil || profile.Validate() != nil {
		return nil, errNativeSandboxHook
	}
	return &profile, nil
}

func prepareNativeSandboxOptions(opts *Options) error {
	if opts.NativeSandbox == nil {
		return errNativeSandboxHook
	}
	profile := *opts.NativeSandbox
	if profile.Validate() != nil || profile.Connector != opts.Connector || profile.HookContract != opts.HookContractID ||
		profile.HookSurface != opts.HookSurface || opts.ManagedEnterprise || opts.SecureClient || opts.ManagedStandalone ||
		opts.Token != "" || opts.AuthenticatedManagedToken != nil || opts.ManagedUnixSocket != "" || opts.GatewayRecovery != nil {
		return errNativeSandboxHook
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errNativeSandboxHook
	}
	opts.NativeSandbox = &profile
	opts.nativeRequestKey = hex.EncodeToString(nonce[:])
	opts.APIAddr = "defenseclaw-native.invalid"
	opts.Home, opts.HookDir = NativeSandboxHookDirectory, NativeSandboxHookDirectory
	opts.FailMode, opts.StrictAvailability = "closed", true
	if opts.MaxBody <= 0 || opts.MaxBody > defaultMaxBody {
		opts.MaxBody = defaultMaxBody
	}
	return nil
}

func nativeSandboxHTTPClient(timeout time.Duration) (*http.Client, error) {
	if runtime.GOOS != "linux" || timeout <= 0 {
		return nil, errNativeSandboxHook
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
			MaxResponseHeaderBytes: 64 << 10,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "defenseclaw-native.invalid:80" {
					return nil, errNativeSandboxHook
				}
				return dialer.DialContext(ctx, "unix", NativeSandboxHookSocket)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// OmniGent keeps its existing Python policy bridge and raw gateway response
// interpretation. This is only its bounded native HTTP exchange, not another
// command-hook decision dialect or policy evaluator.
func runNativeSandboxOmnigent(ctx context.Context, opts Options) int {
	if prepareNativeSandboxOptions(&opts) != nil {
		fmt.Fprintln(opts.Stderr, errNativeSandboxHook)
		return blockExit
	}
	payload, overflow, err := readCapped(opts.Stdin, opts.MaxBody)
	if err != nil || overflow || !json.Valid(payload) {
		return blockExit
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if opts.HTTPClient == nil {
		opts.HTTPClient, err = nativeSandboxHTTPClient(12 * time.Second)
		if err != nil {
			return blockExit
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, nativeSandboxHookOrigin+"/api/v1/omnigent/hook", bytes.NewReader(payload))
	if err != nil {
		return blockExit
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "omnigent-policy/1.0")
	request.Header.Set("X-DefenseClaw-Hook-Idempotency-Key", opts.nativeRequestKey)
	if validTraceparent(opts.TraceParent) {
		request.Header.Set("traceparent", opts.TraceParent)
	}
	if validTracestate(opts.TraceState) {
		request.Header.Set("tracestate", opts.TraceState)
	}
	setUserIdentityHeaders(request, opts)
	response, err := opts.HTTPClient.Do(request)
	if err != nil {
		return blockExit
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, defaultMaxBody+1))
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 || len(body) > int(defaultMaxBody) || !json.Valid(body) {
		return blockExit
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(body, &result) != nil || result == nil {
		return blockExit
	}
	var compact bytes.Buffer
	if json.Compact(&compact, body) != nil {
		return blockExit
	}
	if _, err := fmt.Fprintln(opts.Stdout, compact.String()); err != nil {
		return blockExit
	}
	return 0
}
