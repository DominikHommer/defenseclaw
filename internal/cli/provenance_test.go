// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// A separate provenance command reports the running gateway's quartet,
// never the new CLI process's zero generation. Unproven state is an error.
func TestProvenanceShowOutput(t *testing.T) {
	previous, previousVersion := cfg, appVersion
	t.Cleanup(func() { cfg, appVersion = previous, previousVersion })
	live := version.Provenance{SchemaVersion: version.SchemaVersion, ContentHash: strings.Repeat("a", 64), Generation: 7, BinaryVersion: "1.0.4"}
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}
