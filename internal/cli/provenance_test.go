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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const provenanceTestToken = "provided by secret store"

// provenanceTestGateway serves the authenticated /status of a gateway whose
// process is pid() and, when healthAddr is set, the unauthenticated /health
// of an API listening on healthAddr. It counts the requests it receives and
// those that carried a credential.
type provenanceTestGateway struct {
	live         version.Provenance
	status       int
	pid          func() int
	dataDir      func() string
	healthAddr   string
	requests     atomic.Int32
	credentialed atomic.Int32
}

func newProvenanceTestGateway() *provenanceTestGateway {
	return &provenanceTestGateway{
		live:    version.Provenance{SchemaVersion: version.SchemaVersion, ContentHash: strings.Repeat("a", 64), Generation: 7, BinaryVersion: "1.0.4"},
		status:  http.StatusOK,
		pid:     os.Getpid,
		dataDir: config.DefaultDataPath,
	}
}

func (g *provenanceTestGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.requests.Add(1)
	if r.Header.Get("Authorization") != "" {
		g.credentialed.Add(1)
	}
	if r.URL.Path == "/health" && g.healthAddr != "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"api": map[string]any{"state": "running", "details": map[string]any{"addr": g.healthAddr}}})
		return
	}
	if r.URL.Path != "/status" || r.Header.Get("Authorization") != "Bearer "+provenanceTestToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(g.status)
	if g.status == http.StatusOK {
		_ = json.NewEncoder(w).Encode(map[string]any{"provenance": g.live, "runtime": map[string]any{"pid": g.pid(), "data_dir": g.dataDir()}})
	}
}

// stubProvenanceGateway makes gateway the process provenance trusts, the
// listener holders holders, and gateway the process this home's PID record
// names (which a rejected config.yaml uses to find the API listener).
func stubProvenanceGateway(t *testing.T, gateway provenanceGateway, holders func(host string, port int) ([]daemon.PortHolder, error)) {
	t.Helper()
	stubProvenanceSeams(t)
	provenanceGatewayIdentity = func(context.Context, []net.IP, int) (provenanceGateway, error) { return gateway, nil }
	gatewayPortHolders = holders
	gatewayManagedState = func() (bool, int) { return gateway.PID > 0, gateway.PID }
}

// stubProvenanceSeams restores every provenance seam after the test.
func stubProvenanceSeams(t *testing.T) {
	t.Helper()
	previous, previousVersion := cfg, appVersion
	oldIdentity, oldHolders, oldLookup := provenanceGatewayIdentity, gatewayPortHolders, provenanceLookupIP
	oldState, oldProve, oldListeners := gatewayManagedState, provenanceProveGateway, provenanceGatewayListeners
	t.Cleanup(func() {
		cfg, appVersion = previous, previousVersion
		provenanceGatewayIdentity, gatewayPortHolders, provenanceLookupIP = oldIdentity, oldHolders, oldLookup
		gatewayManagedState, provenanceProveGateway, provenanceGatewayListeners = oldState, oldProve, oldListeners
	})
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
				provenanceGatewayIdentity = func(context.Context, []net.IP, int) (provenanceGateway, error) { return tc.gateway, nil }
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
	provenanceGatewayIdentity = func(context.Context, []net.IP, int) (provenanceGateway, error) {
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
// the config it last applied, and provenance show still reads it. Any
// setting of the rejected file may be the rejected edit, so none is used:
// not the API port or address, not the token or the variable it is read
// from, not the deployment. The per-user gateway is read on the API
// listener its own process holds, with the default gateway token of the
// environment and .env; another listener of the process (here a guardrail
// proxy) and the edited port get no credential. A config that is missing is
// still an error.
func TestProvenanceShowReadsTheRunningGatewayAfterARejectedConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	for _, key := range []string{managed.ConfigPathEnv, managed.DeploymentModeEnv, managed.EnterpriseProfileEnv, "OPENCLAW_GATEWAY_TOKEN"} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", provenanceTestToken)
	t.Setenv("R104_EDITED_TOKEN", "token of the rejected token_env")
	gateway := newProvenanceTestGateway()
	gateway.live.Generation = 41
	server := httptest.NewServer(gateway)
	defer server.Close()
	gateway.healthAddr = server.Listener.Addr().String()
	// The port the rejected edit names: a listener that must get nothing.
	edited := newProvenanceTestGateway()
	editedServer := httptest.NewServer(edited)
	defer editedServer.Close()
	// Another listener of the gateway process: its health is the API's.
	proxy := newProvenanceTestGateway()
	proxy.healthAddr = gateway.healthAddr
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	stubProvenanceGateway(t, provenanceGateway{PID: os.Getpid()}, ownProcessHolds)
	listenerOf := func(server *httptest.Server) daemon.TCPListenAddr {
		addr := server.Listener.Addr().(*net.TCPAddr)
		return daemon.TCPListenAddr{IP: addr.IP, Port: addr.Port}
	}
	held := []daemon.TCPListenAddr{listenerOf(proxyServer), {IP: net.ParseIP("192.0.2.10"), Port: 1}, listenerOf(server)}
	oldListeners := provenanceGatewayListeners
	t.Cleanup(func() { provenanceGatewayListeners = oldListeners })
	provenanceGatewayListeners = func(pid int) ([]daemon.TCPListenAddr, error) {
		if pid != os.Getpid() {
			return nil, errors.New("not the gateway process")
		}
		return held, nil
	}
	_, editedPort, err := net.SplitHostPort(editedServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	section := "gateway:\n  api_bind: 127.0.0.1\n  api_port: " + editedPort + "\n  token: token-of-the-rejected-edit\n  token_env: R104_EDITED_TOKEN\n"
	path := filepath.Join(home, "config.yaml")
	for name, body := range map[string]string{
		"schema-invalid": "config_version: 9\n" + section + "r104_rejected_key: true\n",
		"not YAML":       "config_version: 9\n" + section + "guardrail:\n  mode: [action\n",
		"reordered":      "guardrail: {mode: [\n" + section,
		// A rejected edit that names Secure Client does not stop the
		// gateway from being read.
		"secure client": "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\n" + section + "r104_rejected_key: true\n",
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
			if edited.requests.Load() != 0 || proxy.credentialed.Load() != 0 {
				t.Fatalf("the edited port got %d requests, the proxy %d with a credential", edited.requests.Load(), proxy.credentialed.Load())
			}
		})
	}
	// This home's PID record names a process that is not this account's
	// gateway: nothing is asked, not even /health.
	other := otherProvenanceProgram(t)
	for _, candidate := range []int{other.Process.Pid, 0} {
		gatewayManagedState = func() (bool, int) { return candidate > 0, candidate }
		before := gateway.requests.Load() + proxy.requests.Load() + edited.requests.Load()
		cmd, _, _ := provenanceTestCommand()
		if err := prepareProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "gateway not verified") {
			t.Fatalf("PID record naming %d: %v", candidate, err)
		}
		if gateway.requests.Load()+proxy.requests.Load()+edited.requests.Load() != before {
			t.Fatalf("PID record naming %d: a listener got a request", candidate)
		}
	}
	gatewayManagedState = func() (bool, int) { return true, os.Getpid() }
	// The gateway process holds no API listener: the read fails and no
	// listener gets the credential.
	held = []daemon.TCPListenAddr{listenerOf(proxyServer)}
	before := gateway.requests.Load()
	cmd, _, _ := provenanceTestCommand()
	if err := prepareProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "defenseclaw-gateway status") {
		t.Fatalf("no API listener: %v", err)
	}
	if proxy.credentialed.Load() != 0 || edited.requests.Load() != 0 || gateway.requests.Load() != before {
		t.Fatal("a listener got a request without a proven API listener")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cmd, _, _ = provenanceTestCommand()
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
	c, err := provenanceAppliedConfig(context.Background(), errors.New("config gateway.api_port 1 is invalid"))
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
	if _, err := provenanceAppliedConfig(context.Background(), errors.New("rejected")); err == nil {
		t.Fatal("a standalone deployment without its runtime descriptor fell back on the rejected file")
	}
	for _, unreadable := range []error{os.ErrNotExist, os.ErrPermission} {
		if _, err := provenanceAppliedConfig(context.Background(), unreadable); err == nil {
			t.Fatalf("%v fell back", unreadable)
		}
	}
}

// otherProvenanceProgram starts a long-running program of this account that
// is not this binary.
func otherProvenanceProgram(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if runtime.GOOS == "windows" {
		cmd = exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"), "-n", "60", "127.0.0.1")
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// Provenance sends the gateway token only to the process the kernel names
// as the holder of the API listener, and only once the operating system
// shows that process runs as this account from this DefenseClaw binary. No
// PID record is read: this home's record, whatever it names (here the
// strongest kind, naming this process), proves nothing. Every other holder
// gets no request: another program of this account, another account's
// process, a process that has exited, an unknown or shared holder, a
// listener that cannot be inspected. A process proven and then replaced
// before the connection gets nothing, and the gateway of another home of
// this account (same account, same binary) is not this home's provenance.
func TestProvenanceShowSendsTheTokenOnlyToAGatewayProvenNow(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("gateway processes cannot be proven on %s", runtime.GOOS)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	for _, key := range []string{managed.DeploymentModeEnv, managed.EnterpriseProfileEnv} {
		t.Setenv(key, "")
	}
	gateway := newProvenanceTestGateway()
	server := httptest.NewServer(gateway)
	defer server.Close()
	stubProvenanceSeams(t)
	cfg = provenanceTestConfig(t, server)
	pid := os.Getpid()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(map[string]any{"pid": pid, "executable": executable, "data_dir": home,
		"start_identity": provenanceTestStartIdentity(t, home), "start_time": time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, daemon.PIDFileName), record, 0o600); err != nil {
		t.Fatal(err)
	}
	if !daemon.New(home).HasManagedProcessIdentity(pid) {
		t.Fatal("precondition: this home's PID record must be the strongest kind")
	}
	other := otherProvenanceProgram(t)
	exited := otherProvenanceProgram(t)
	_ = exited.Process.Kill()
	_ = exited.Wait()
	foreign := 1 // root's init: another account, or another program for root
	if runtime.GOOS == "windows" {
		foreign = 4 // System
	}
	for _, tc := range []struct {
		name    string
		holders []daemon.PortHolder
		err     error
	}{
		{"another program of this account", []daemon.PortHolder{{PID: other.Process.Pid}}, nil},
		{"another account's process", []daemon.PortHolder{{PID: foreign, UID: 0}}, nil},
		{"a process that has exited", []daemon.PortHolder{{PID: exited.Process.Pid}}, nil},
		{"an unknown holder", []daemon.PortHolder{{PID: 0, UID: -1}}, nil},
		{"the gateway and another program", []daemon.PortHolder{{PID: pid}, {PID: other.Process.Pid}}, nil},
		{"no listener seen", nil, daemon.ErrNoListener},
		{"inspection failed", nil, errors.New("inspection denied")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gatewayPortHolders = func(string, int) ([]daemon.PortHolder, error) { return tc.holders, tc.err }
			before := gateway.requests.Load()
			cmd, buf, _ := provenanceTestCommand()
			err := runProvenanceShow(cmd, nil)
			if err == nil || !strings.Contains(err.Error(), "gateway not verified") ||
				!strings.Contains(err.Error(), "the gateway token was not sent") || buf.Len() != 0 {
				t.Fatalf("output=%q error=%v", buf, err)
			}
			if gateway.requests.Load() != before || gateway.credentialed.Load() != 0 {
				t.Fatalf("sent %d requests, %d with the gateway credential, to an unproven holder",
					gateway.requests.Load()-before, gateway.credentialed.Load())
			}
		})
	}

	// The holder is this binary's process of this account: it is read.
	gatewayPortHolders = ownProcessHolds
	cfg.Gateway.Token = provenanceTestToken
	cmd, buf, _ := provenanceTestCommand()
	if err := runProvenanceShow(cmd, nil); err != nil || !strings.Contains(buf.String(), "generation: 7\n") {
		t.Fatalf("a proven gateway: output=%q error=%v", buf, err)
	}

	// Proven, then another process by the time of the connection.
	proofs := 0
	provenanceProveGateway = func(got int) (string, error) {
		proofs++
		return "start-" + strconv.Itoa(proofs), nil
	}
	before := gateway.requests.Load()
	cmd, buf, _ = provenanceTestCommand()
	if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "gateway not verified") || buf.Len() != 0 ||
		gateway.requests.Load() != before {
		t.Fatalf("a process replaced after its proof: output=%q error=%v requests=%d", buf, err, gateway.requests.Load()-before)
	}
	provenanceProveGateway = daemon.ProveOwnGateway

	// The gateway of another home of this account answers as itself.
	gateway.dataDir = func() string { return filepath.Join(home, "another-home") }
	cmd, buf, _ = provenanceTestCommand()
	if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "another DefenseClaw home") || buf.Len() != 0 {
		t.Fatalf("another home's gateway: output=%q error=%v", buf, err)
	}
}

// provenanceTestStartIdentity is the kernel start identity of this test
// process, read from the record a daemon child writes of itself.
func provenanceTestStartIdentity(t *testing.T, home string) string {
	t.Helper()
	t.Setenv(daemon.EnvDaemon, "1")
	t.Setenv(daemon.EnvDataDir, home)
	if err := daemon.RecordAppliedAuth(daemon.AppliedAuth{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(daemon.EnvDaemon, "")
	t.Setenv(daemon.EnvDataDir, "")
	path := filepath.Join(home, daemon.AppliedAuthFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var record struct {
		StartIdentity string `json:"start_identity"`
	}
	if err := json.Unmarshal(raw, &record); err != nil || record.StartIdentity == "" {
		t.Fatalf("start identity of the test process: %q, %v", record.StartIdentity, err)
	}
	return record.StartIdentity
}

// A per-user gateway authenticates with the token it started with and
// records the token_env and inline token of that start (daemon.AppliedAuth).
// With no default gateway token set, provenance still sends that token, and
// only it, after config.yaml was edited into a state the gateway rejected,
// or a valid edit of the token that the gateway holds until a restart: an
// inline token, or one read from a custom token_env. The token and token_env
// of the edited file are never used. A record of another process is none.
func TestProvenanceShowAuthenticatesWithTheCredentialTheGatewayStartedWith(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	for _, key := range []string{managed.ConfigPathEnv, managed.DeploymentModeEnv, managed.EnterpriseProfileEnv,
		"OPENCLAW_GATEWAY_TOKEN", "DEFENSECLAW_GATEWAY_TOKEN"} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
	t.Setenv("R104_EDITED_TOKEN", "token of the edited token_env")
	t.Setenv("R104_APPLIED_TOKEN", provenanceTestToken)
	gateway := newProvenanceTestGateway()
	gateway.live.Generation = 43
	server := httptest.NewServer(gateway)
	defer server.Close()
	gateway.healthAddr = server.Listener.Addr().String()
	stubProvenanceGateway(t, provenanceGateway{PID: os.Getpid()}, ownProcessHolds)
	addr := server.Listener.Addr().(*net.TCPAddr)
	oldListeners := provenanceGatewayListeners
	t.Cleanup(func() { provenanceGatewayListeners = oldListeners })
	provenanceGatewayListeners = func(int) ([]daemon.TCPListenAddr, error) {
		return []daemon.TCPListenAddr{{IP: addr.IP, Port: addr.Port}}, nil
	}
	// This test process is the gateway the record names.
	t.Setenv(daemon.EnvDaemon, "1")
	t.Setenv(daemon.EnvDataDir, home)
	path := filepath.Join(home, "config.yaml")
	edited := "gateway:\n  token: token-of-the-edit\n  token_env: R104_EDITED_TOKEN\n"
	for _, tc := range []struct {
		name    string
		applied daemon.AppliedAuth
		body    string // a rejected config.yaml; "" is a valid edit the gateway holds
	}{
		{"inline token, rejected file", daemon.AppliedAuth{Token: provenanceTestToken}, "config_version: 9\n" + edited + "r104_rejected_key: true\n"},
		{"custom token_env, rejected file", daemon.AppliedAuth{TokenEnv: "R104_APPLIED_TOKEN"}, "guardrail: {mode: [\n" + edited},
		{"inline token, held edit", daemon.AppliedAuth{Token: provenanceTestToken}, ""},
		{"custom token_env, held edit", daemon.AppliedAuth{TokenEnv: "R104_APPLIED_TOKEN", Token: "inline token the variable overrides"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := daemon.RecordAppliedAuth(tc.applied); err != nil {
				t.Fatal(err)
			}
			cmd, out, _ := provenanceTestCommand()
			if tc.body != "" {
				if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := prepareProvenanceShow(cmd, nil); err != nil {
					t.Fatalf("a rejected config.yaml stopped the read: %v", err)
				}
			} else {
				cfg = provenanceTestConfig(t, server)
				cfg.Gateway.Token, cfg.Gateway.TokenEnv = "token-of-the-edit", "R104_EDITED_TOKEN"
			}
			if err := runProvenanceShow(cmd, nil); err != nil || !strings.Contains(out.String(), "generation: 43\n") {
				t.Fatalf("output=%q error=%v", out, err)
			}
		})
	}
	// The record a gateway that ran before under another PID left behind:
	// nothing in it is sent.
	stale, err := json.Marshal(map[string]any{"pid": os.Getpid() + 1, "start_identity": "1", "token": provenanceTestToken})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, daemon.AppliedAuthFileName), stale, 0o600); err != nil {
		t.Fatal(err)
	}
	before := gateway.credentialed.Load()
	cfg = provenanceTestConfig(t, server)
	cfg.Gateway.Token, cfg.Gateway.TokenEnv = "", ""
	cmd, out, _ := provenanceTestCommand()
	if err := runProvenanceShow(cmd, nil); err == nil || out.Len() != 0 || gateway.credentialed.Load() != before {
		t.Fatalf("a stale record: output=%q error=%v credentialed=%d", out, err, gateway.credentialed.Load()-before)
	}
}
