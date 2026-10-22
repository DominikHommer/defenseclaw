// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func TestProvenanceShowOutput(t *testing.T) {
	t.Parallel()
	version.ResetForTesting()
	version.SetBinaryVersion("9.9.9-test")
	version.SetContentHash([]byte("abc"))

	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	appVersion = "9.9.9-test"
	if err := runProvenanceShow(cmd, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, s := range []string{"schema_version:", "content_hash:", "generation:", "binary_version:"} {
		if !bytes.Contains([]byte(out), []byte(s)) {
			t.Fatalf("stdout missing %q: %s", s, out)
		}
	}
}

func TestPerUserProvenanceWithRejectedCustomTokenConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("W7_CUSTOM_GATEWAY_TOKEN", "provided by the test environment")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/health" || r.Header.Get("Authorization") != "" || r.Header.Get("X-DefenseClaw-Token") != "" {
			t.Error("provenance depended on rejected authentication fields")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"provenance": map[string]any{
			"schema_version": 7, "content_hash": strings.Repeat("b", 64), "generation": 42, "binary_version": "1.0.4-running",
		}})
	}))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	previousState, previousHolder := gatewayManagedState, gatewayPortHolder
	t.Cleanup(func() { gatewayManagedState, gatewayPortHolder = previousState, previousHolder })
	gatewayManagedState = func() (bool, int) { return true, os.Getpid() }
	for _, invalid := range []string{"guardrail:\n  mode: invalid\n", "gateway:\n  token_env: [invalid]\n"} {
		// token_env can itself be the rejected field; no credential read
		// from this document can authenticate the last-applied gateway.
		gatewayFields := fmt.Sprintf("  api_bind: 127.0.0.1\n  api_port: %d\n", port)
		body := "config_version: 9\n"
		if strings.HasPrefix(invalid, "gateway:") {
			body += "gateway:\n" + gatewayFields + "  token_env: [invalid]\n"
		} else {
			body += "gateway:\n" + gatewayFields + "  token_env: W7_CUSTOM_GATEWAY_TOKEN\n" + invalid
		}
		path := filepath.Join(home, "config.yaml")
		t.Setenv("DEFENSECLAW_CONFIG", path)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var output strings.Builder
		cmd := &cobra.Command{}
		cmd.SetOut(&output)
		if err := runProvenanceShow(cmd, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "content_hash: "+strings.Repeat("b", 64)) ||
			!strings.Contains(output.String(), "generation: 42") {
			t.Fatalf("running provenance was hidden by rejected config: %s", output.String())
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("provenance health reads=%d", requests.Load())
	}
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{}, errors.New("unproven listener")
	}
	if err := runProvenanceShow(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "defenseclaw-gateway status") {
		t.Fatalf("unproven listener did not fail closed with a next command: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatal("unproven listener received a provenance request")
	}
}
