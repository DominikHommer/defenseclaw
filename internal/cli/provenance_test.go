// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// A separate provenance command reports the running gateway's quartet,
// never the new CLI process's zero generation. Unproven state is an error.
func TestProvenanceShowOutput(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	previous, previousVersion := cfg, appVersion
	t.Cleanup(func() { cfg, appVersion = previous, previousVersion })
	oldPID, oldHolder := provenanceGatewayPID, gatewayPortHolder
	t.Cleanup(func() { provenanceGatewayPID, gatewayPortHolder = oldPID, oldHolder })
	provenanceGatewayPID = func(context.Context) (int, error) { return os.Getpid(), nil }
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: os.Getpid()}, nil
	}
	live := version.Provenance{SchemaVersion: version.SchemaVersion, ContentHash: strings.Repeat("a", 64), Generation: 7, BinaryVersion: "1.0.4"}
	status := http.StatusOK
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/status" || r.Header.Get("Authorization") != "Bearer provided by secret store" {
			t.Errorf("provenance requested %s without the gateway credential", r.URL.Path)
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{"provenance": live})
		}
	}))
	defer server.Close()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg = config.DefaultConfig()
	cfg.Gateway.APIBind = host
	cfg.Gateway.APIPort, _ = strconv.Atoi(port)
	cfg.Gateway.Token = "provided by secret store"
	cfg.Gateway.TokenEnv = ""
	appVersion = "cli-test"
	buf := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetContext(context.Background())
	for _, generation := range []uint64{7, 8} {
		live.Generation = generation
		buf.Reset()
		if err := runProvenanceShow(cmd, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "generation: "+strconv.FormatUint(generation, 10)+"\n") ||
			!strings.Contains(buf.String(), "content_hash: "+live.ContentHash+"\n") ||
			!strings.Contains(buf.String(), "binary_version: 1.0.4\n") {
			t.Fatalf("not the applied gateway provenance: %s", buf)
		}
	}
	status = http.StatusForbidden
	buf.Reset()
	if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "defenseclaw-gateway status") || buf.Len() != 0 {
		t.Fatalf("unproven provenance: output=%q error=%v", buf, err)
	}
	for _, mode := range []string{"unmanaged_byod", managed.DeploymentModeManagedEnterprise} {
		cfg.DeploymentMode = mode
		cfg.Enterprise.Profile = managed.ProfileStandalone
		for _, reason := range []string{"no process", "unknown listener", "foreign listener", "inspection failed"} {
			t.Run(mode+"/"+reason, func(t *testing.T) {
				provenanceGatewayPID = func(context.Context) (int, error) { return os.Getpid(), nil }
				gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
					switch reason {
					case "foreign listener":
						return daemon.PortHolder{PID: os.Getpid() + 1}, nil
					case "inspection failed":
						return daemon.PortHolder{}, errors.New("inspection denied")
					default:
						return daemon.PortHolder{}, nil
					}
				}
				if reason == "no process" {
					provenanceGatewayPID = func(context.Context) (int, error) { return 0, nil }
				}
				before := requests.Load()
				buf.Reset()
				if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "defenseclaw-gateway status") || buf.Len() != 0 {
					t.Fatalf("unproven listener: output=%q error=%v", buf, err)
				}
				if requests.Load() != before {
					t.Fatal("sent an HTTP request or gateway credential to an unproven listener")
				}
			})
		}
	}
}
