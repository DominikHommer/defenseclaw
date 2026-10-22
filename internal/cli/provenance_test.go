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
	"path/filepath"
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

const provenanceTestToken = "provided by secret store"

// provenanceTestGateway serves the authenticated /status of a gateway whose
// process is pid() and counts the requests it receives.
type provenanceTestGateway struct {
	live     version.Provenance
	status   int
	pid      func() int
	requests atomic.Int32
}

func newProvenanceTestGateway() *provenanceTestGateway {
	return &provenanceTestGateway{
		live:   version.Provenance{SchemaVersion: version.SchemaVersion, ContentHash: strings.Repeat("a", 64), Generation: 7, BinaryVersion: "1.0.4"},
		status: http.StatusOK,
		pid:    os.Getpid,
	}
}

func (g *provenanceTestGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.requests.Add(1)
	if r.URL.Path != "/status" || r.Header.Get("Authorization") != "Bearer "+provenanceTestToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(g.status)
	if g.status == http.StatusOK {
		_ = json.NewEncoder(w).Encode(map[string]any{"provenance": g.live, "runtime": map[string]any{"pid": g.pid()}})
	}
}

// stubProvenanceGateway makes gateway the process provenance trusts and the
// listener holders holders.
func stubProvenanceGateway(t *testing.T, gateway provenanceGateway, holders func(host string, port int) ([]daemon.PortHolder, error)) {
	t.Helper()
	previous, previousVersion := cfg, appVersion
	oldIdentity, oldHolders, oldLookup := provenanceGatewayIdentity, gatewayPortHolders, provenanceLookupIP
	t.Cleanup(func() {
		cfg, appVersion = previous, previousVersion
		provenanceGatewayIdentity, gatewayPortHolders, provenanceLookupIP = oldIdentity, oldHolders, oldLookup
	})
	provenanceGatewayIdentity = func(context.Context) (provenanceGateway, error) { return gateway, nil }
	gatewayPortHolders = holders
	appVersion = "cli-test"
}

func provenanceTestConfig(t *testing.T, server *httptest.Server) *config.Config {
	t.Helper()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	number, _ := strconv.Atoi(port)
	return provenanceTestConfigAt(host, number)
}

func provenanceTestConfigAt(host string, port int) *config.Config {
	c := config.DefaultConfig()
	c.Gateway.APIBind = host
	c.Gateway.APIPort = port
	c.Gateway.Token = provenanceTestToken
	c.Gateway.TokenEnv = ""
	return c
}

func provenanceTestCommand() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetContext(context.Background())
	return cmd, out, errOut
}

func ownProcessHolds(string, int) ([]daemon.PortHolder, error) {
	return []daemon.PortHolder{{PID: os.Getpid()}}, nil
}

// A separate provenance command reports the running gateway's quartet,
// never the new CLI process's zero generation. Unproven state is an error.
func TestProvenanceShowOutput(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	gateway := newProvenanceTestGateway()
	server := httptest.NewServer(gateway)
	defer server.Close()
	stubProvenanceGateway(t, provenanceGateway{PID: os.Getpid()}, ownProcessHolds)
	cfg = provenanceTestConfig(t, server)
	cmd, buf, _ := provenanceTestCommand()
	for _, generation := range []uint64{7, 8} {
		gateway.live.Generation = generation
		buf.Reset()
		if err := runProvenanceShow(cmd, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "generation: "+strconv.FormatUint(generation, 10)+"\n") ||
			!strings.Contains(buf.String(), "content_hash: "+gateway.live.ContentHash+"\n") ||
			!strings.Contains(buf.String(), "binary_version: 1.0.4\n") {
			t.Fatalf("not the applied gateway provenance: %s", buf)
		}
	}
	gateway.status = http.StatusForbidden
	buf.Reset()
	if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "defenseclaw-gateway status") || buf.Len() != 0 {
		t.Fatalf("unproven provenance: output=%q error=%v", buf, err)
	}
	// An authenticated answer from another process is not the gateway's.
	gateway.status, gateway.pid = http.StatusOK, func() int { return os.Getpid() + 1 }
	buf.Reset()
	if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "did not come from the gateway process") || buf.Len() != 0 {
		t.Fatalf("answer of another process: output=%q error=%v", buf, err)
	}
	gateway.pid = os.Getpid
	pid := os.Getpid()
	for _, mode := range []string{"unmanaged_byod", managed.DeploymentModeManagedEnterprise} {
		cfg.DeploymentMode = mode
		cfg.Enterprise.Profile = managed.ProfileStandalone
		for _, tc := range []struct {
			reason  string
			gateway provenanceGateway
			holders []daemon.PortHolder
			err     error
		}{
			{"no process", provenanceGateway{}, []daemon.PortHolder{{PID: pid}}, nil},
			{"unknown listener", provenanceGateway{PID: pid}, []daemon.PortHolder{{PID: 0, UID: -1}}, nil},
			{"foreign listener", provenanceGateway{PID: pid}, []daemon.PortHolder{{PID: pid + 1}}, nil},
			{"inspection failed", provenanceGateway{PID: pid}, nil, errors.New("inspection denied")},
			{"no holder", provenanceGateway{PID: pid}, nil, nil},
			// PID 1 counts only as the socket-activating service manager.
			{"service manager not activating", provenanceGateway{PID: pid}, []daemon.PortHolder{{PID: 1}, {PID: pid}}, nil},
			{"only the service manager", provenanceGateway{PID: pid, SocketManagerPID: 1}, []daemon.PortHolder{{PID: 1}}, nil},
			{"a third holder", provenanceGateway{PID: pid, SocketManagerPID: 1}, []daemon.PortHolder{{PID: 1}, {PID: pid}, {PID: pid + 1}}, nil},
		} {
			t.Run(mode+"/"+tc.reason, func(t *testing.T) {
				provenanceGatewayIdentity = func(context.Context) (provenanceGateway, error) { return tc.gateway, nil }
				gatewayPortHolders = func(string, int) ([]daemon.PortHolder, error) { return tc.holders, tc.err }
				before := gateway.requests.Load()
				buf.Reset()
				if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "defenseclaw-gateway status") || buf.Len() != 0 {
					t.Fatalf("unproven listener: output=%q error=%v", buf, err)
				}
				if gateway.requests.Load() != before {
					t.Fatal("sent an HTTP request or gateway credential to an unproven listener")
				}
			})
		}
	}
	// Under socket activation the service manager holds the socket beside
	// the gateway.
	provenanceGatewayIdentity = func(context.Context) (provenanceGateway, error) {
		return provenanceGateway{PID: pid, SocketManagerPID: 1}, nil
	}
	gatewayPortHolders = func(string, int) ([]daemon.PortHolder, error) {
		return []daemon.PortHolder{{PID: 1, Command: "systemd"}, {PID: pid}}, nil
	}
	buf.Reset()
	if err := runProvenanceShow(cmd, nil); err != nil || !strings.Contains(buf.String(), "generation: 8\n") {
		t.Fatalf("socket-activated gateway: output=%q error=%v", buf, err)
	}
}

// gateway.api_bind localhost is a supported loopback bind. The name is
// resolved once to loopback addresses, the dial is pinned to one of them,
// and the holder of that exact address is checked.
func TestProvenanceShowLocalhostBind(t *testing.T) {
	gateway := newProvenanceTestGateway()
	server := httptest.NewServer(gateway)
	defer server.Close()
	var checked []string
	stubProvenanceGateway(t, provenanceGateway{PID: os.Getpid()}, func(host string, port int) ([]daemon.PortHolder, error) {
		checked = append(checked, host)
		if host != "127.0.0.1" {
			return nil, daemon.ErrNoListener
		}
		return []daemon.PortHolder{{PID: os.Getpid()}}, nil
	})
	base := provenanceTestConfig(t, server)
	cmd, buf, _ := provenanceTestCommand()
	for _, tc := range []struct {
		bind     string
		resolved []net.IPAddr
		lookup   error
		ok       bool
	}{
		{"localhost", []net.IPAddr{{IP: net.IPv6loopback}, {IP: net.IPv4(127, 0, 0, 1)}}, nil, true},
		{"LOCALHOST", nil, nil, true},
		{"localhost.", nil, errors.New("no such host"), true},
		{"[localhost]", []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}, nil, true}, // localhost is loopback whatever the resolver says
		{"gateway.internal.test", []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil, true},
		{"gateway.internal.test", []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}, {IP: net.ParseIP("10.0.0.7")}}, nil, false},
		{"gateway.internal.test", nil, errors.New("no such host"), false},
		{"10.0.0.7", nil, nil, false},
		{"::ffff:10.0.0.7", nil, nil, false},
	} {
		t.Run(tc.bind, func(t *testing.T) {
			lookups := 0
			provenanceLookupIP = func(context.Context, string) ([]net.IPAddr, error) {
				lookups++
				return tc.resolved, tc.lookup
			}
			c := *base
			c.Gateway.APIBind = tc.bind
			cfg = &c
			checked = nil
			before := gateway.requests.Load()
			buf.Reset()
			err := runProvenanceShow(cmd, nil)
			if !tc.ok {
				if err == nil || buf.Len() != 0 || gateway.requests.Load() != before {
					t.Fatalf("non-loopback bind %s: output=%q error=%v", tc.bind, buf, err)
				}
				return
			}
			if err != nil || !strings.Contains(buf.String(), "generation: 7\n") {
				t.Fatalf("bind %s: output=%q error=%v", tc.bind, buf, err)
			}
			if lookups > 1 || len(checked) == 0 || checked[len(checked)-1] != "127.0.0.1" {
				t.Fatalf("bind %s: %d lookups, holders checked at %q; want the pinned 127.0.0.1", tc.bind, lookups, checked)
			}
		})
	}
}

// When the gateway rejected an edit of config.yaml, it keeps running on
// the config it last applied, and provenance show still reads it. The
// credential stays the one the gateway uses (the environment and .env).
// A config that is missing is still an error.
func TestProvenanceShowReadsTheRunningGatewayAfterARejectedConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	for _, key := range []string{managed.ConfigPathEnv, managed.DeploymentModeEnv, managed.EnterpriseProfileEnv, "OPENCLAW_GATEWAY_TOKEN"} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", provenanceTestToken)
	gateway := newProvenanceTestGateway()
	gateway.live.Generation = 41
	server := httptest.NewServer(gateway)
	defer server.Close()
	stubProvenanceGateway(t, provenanceGateway{PID: os.Getpid()}, ownProcessHolds)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	section := "gateway:\n  api_bind: 127.0.0.1\n  api_port: " + port + "\n  token_env: DEFENSECLAW_GATEWAY_TOKEN\n"
	path := filepath.Join(home, "config.yaml")
	for name, body := range map[string]string{
		"schema-invalid": "config_version: 9\n" + section + "r104_rejected_key: true\n",
		"not YAML":       "config_version: 9\n" + section + "guardrail:\n  mode: [action\n",
		"reordered":      "guardrail: {mode: [\n" + section,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd, out, errOut := provenanceTestCommand()
			if err := prepareProvenanceShow(cmd, nil); err != nil {
				t.Fatalf("a rejected config.yaml stopped the read: %v", err)
			}
			if err := runProvenanceShow(cmd, nil); err != nil || !strings.Contains(out.String(), "generation: 41\n") {
				t.Fatalf("output=%q error=%v", out, err)
			}
			if !strings.Contains(errOut.String(), "keeps the config it last applied") {
				t.Fatalf("no warning about the rejected config: %q", errOut)
			}
		})
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cmd, _, _ := provenanceTestCommand()
	if err := prepareProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "defenseclaw-gateway status") {
		t.Fatalf("a missing config.yaml: %v", err)
	}
}

// A standalone deployment's API address comes from the runtime descriptor
// and its credential fields from the last applied config; the rejected
// config.yaml is not read.
func TestProvenanceAppliedConfigOfAStandaloneDeploymentIgnoresTheRejectedFile(t *testing.T) {
	rejected := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(rejected, []byte("gateway:\n  api_bind: 10.9.9.9\n  api_port: 1\n  token: rejected\n  token_env: REJECTED_TOKEN\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.ConfigPathEnv, rejected)
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	oldDeployment, oldCommitted := managedStandaloneAdminDeployment, provenanceCommittedConfig
	t.Cleanup(func() { managedStandaloneAdminDeployment, provenanceCommittedConfig = oldDeployment, oldCommitted })
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, &managed.RuntimeDescriptor{APIAddr: managed.StandaloneAPIAddr}, nil
	}
	provenanceCommittedConfig = func() ([]byte, error) {
		return []byte("config_version: 9\ngateway:\n  api_port: 18970\n  token_env: APPLIED_TOKEN\n"), nil
	}
	c, err := provenanceAppliedConfig(errors.New("config gateway.api_port 1 is invalid"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.StandaloneEnterprise() || c.Gateway.APIBind != "127.0.0.1" || c.Gateway.APIPort != 18970 ||
		c.Gateway.Token != "" || c.Gateway.TokenEnv != "APPLIED_TOKEN" {
		t.Fatalf("applied endpoint = %+v", c.Gateway)
	}
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, nil, managed.ErrNoRuntimeDescriptor
	}
	if _, err := provenanceAppliedConfig(errors.New("rejected")); err == nil {
		t.Fatal("a standalone deployment without its runtime descriptor fell back on the rejected file")
	}
	for _, unreadable := range []error{os.ErrNotExist, os.ErrPermission} {
		if _, err := provenanceAppliedConfig(unreadable); err == nil {
			t.Fatalf("%v fell back", unreadable)
		}
	}
}
