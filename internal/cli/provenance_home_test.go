// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// provenanceRejectedConfig is a config.yaml the strict load rejects.
const provenanceRejectedConfig = "config_version: 9\nr104_rejected_key: true\n"

// isolateProvenanceHome points DEFENSECLAW_HOME at a new home with no
// gateway token in the environment and no deployment pins, and returns it.
func isolateProvenanceHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	for _, key := range []string{managed.ConfigPathEnv, managed.DeploymentModeEnv, managed.EnterpriseProfileEnv,
		"OPENCLAW_GATEWAY_TOKEN", "DEFENSECLAW_GATEWAY_TOKEN", daemon.EnvDaemon, daemon.EnvDataDir} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
	return home
}

// serveProvenanceTestGateway serves gateway with its /health naming that
// listener as the API, as the listener that process pid holds.
func serveProvenanceTestGateway(t *testing.T, gateway *provenanceTestGateway, pid int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(gateway)
	t.Cleanup(server.Close)
	gateway.healthAddr = server.Listener.Addr().String()
	gateway.pid = func() int { return pid }
	addr := server.Listener.Addr().(*net.TCPAddr)
	provenanceGatewayListeners = func(got int) ([]daemon.TCPListenAddr, error) {
		if got != pid {
			return nil, os.ErrNotExist
		}
		return []daemon.TCPListenAddr{{IP: addr.IP, Port: addr.Port}}, nil
	}
	gatewayPortHolders = func(string, int) ([]daemon.PortHolder, error) { return []daemon.PortHolder{{PID: pid}}, nil }
	provenanceGatewayAccepts(pid)
	gatewayManagedState = func() (bool, int) { return true, pid }
	return server
}

// The finding: with a rejected config.yaml in home A, this home's PID
// record (whatever kind) names the live gateway of home B of the same
// account. That process runs as this account from this binary, so it passed
// the proof; it got /health, and then /status with home A's token, and the
// other data directory was refused only after it answered. Now the
// operating system shows which home the process was started for, before
// anything is sent: B's gateway gets no request at all. This home's own
// gateway is still read after a rejected file.
func TestProvenanceShowSendsNothingToAnotherHomesGatewayAfterARejectedConfig(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("gateway processes cannot be proven on %s", runtime.GOOS)
	}
	home := isolateProvenanceHome(t)
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", provenanceTestToken)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(provenanceRejectedConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	stubProvenanceSeams(t)
	otherHome := filepath.Join(t.TempDir(), "home-b")
	other := newProvenanceTestGateway()
	other.dataDir = func() string { return otherHome }
	serveProvenanceTestGateway(t, other, startProvenanceTestGateway(t, otherHome))

	cmd, out, _ := provenanceTestCommand()
	err := prepareProvenanceShow(cmd, nil)
	if err == nil {
		err = runProvenanceShow(cmd, nil)
	}
	if err == nil || !strings.Contains(err.Error(), "gateway not verified") ||
		!strings.Contains(err.Error(), "another DefenseClaw home") || out.Len() != 0 {
		t.Fatalf("another home's gateway: output=%q error=%v", out, err)
	}
	if other.requests.Load() != 0 || other.credentialed.Load() != 0 {
		t.Fatalf("another home's gateway got %d requests, %d with this home's token",
			other.requests.Load(), other.credentialed.Load())
	}

	// This home's gateway, after the same rejected file, is read.
	own := newProvenanceTestGateway()
	own.live.Generation = 52
	serveProvenanceTestGateway(t, own, startProvenanceTestGateway(t, home))
	cmd, out, _ = provenanceTestCommand()
	if err := prepareProvenanceShow(cmd, nil); err != nil {
		t.Fatalf("this home's gateway after a rejected config.yaml: %v", err)
	}
	if err := runProvenanceShow(cmd, nil); err != nil || !strings.Contains(out.String(), "generation: 52\n") {
		t.Fatalf("this home's gateway: output=%q error=%v", out, err)
	}
}

// A per-user gateway started with an explicit data_dir B reads its token
// from B/.env (or the environment) and reports B as runtime.data_dir. It
// records B with the credential configuration it started with
// (daemon.AppliedAuth). Before, a rejected config.yaml left provenance with
// the default data directory: B/.env was never read (HTTP 401), and a token
// from the environment was sent but B's answer was refused as another home.
// A valid data_dir edit the gateway holds until a restart failed the same
// way. Now the data directory the gateway runs on gives both the .env to
// read and the home check, and the .env of the edited data_dir is not read.
func TestProvenanceShowReadsAGatewayOnTheDataDirItStartedWith(t *testing.T) {
	home := isolateProvenanceHome(t)
	dataDir := filepath.Join(t.TempDir(), "data-b")
	edited := filepath.Join(t.TempDir(), "data-c")
	for dir, token := range map[string]string{dataDir: provenanceTestToken, edited: "token of the edited data_dir"} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN="+token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gateway := newProvenanceTestGateway()
	gateway.live.Generation = 61
	gateway.dataDir = func() string { return dataDir }
	stubProvenanceGateway(t, provenanceGateway{PID: os.Getpid()}, ownProcessHolds)
	server := serveProvenanceTestGateway(t, gateway, os.Getpid())
	// This test process is the gateway the record names.
	t.Setenv(daemon.EnvDaemon, "1")
	t.Setenv(daemon.EnvDataDir, home)
	path := filepath.Join(home, "config.yaml")
	for _, tc := range []struct {
		name    string
		applied daemon.AppliedAuth
		shell   map[string]string
		rejects bool // a rejected config.yaml; else a data_dir edit the gateway holds
	}{
		{"token in the data_dir .env, rejected file", daemon.AppliedAuth{DataDir: dataDir}, nil, true},
		{"token in the environment, rejected file", daemon.AppliedAuth{TokenEnv: "R104_SHELL_TOKEN", DataDir: dataDir},
			map[string]string{"R104_SHELL_TOKEN": provenanceTestToken}, true},
		{"token in the data_dir .env, held data_dir edit", daemon.AppliedAuth{DataDir: dataDir}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.shell {
				t.Setenv(key, value)
			}
			t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
			_ = os.Unsetenv("DEFENSECLAW_GATEWAY_TOKEN")
			if err := daemon.RecordAppliedAuth(tc.applied); err != nil {
				t.Fatal(err)
			}
			before := gateway.requests.Load()
			cmd, out, _ := provenanceTestCommand()
			if tc.rejects {
				if err := os.WriteFile(path, []byte(provenanceRejectedConfig), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := prepareProvenanceShow(cmd, nil); err != nil {
					t.Fatalf("a rejected config.yaml stopped the read: %v", err)
				}
			} else {
				// The CLI loaded the edited config and the edited
				// data_dir's .env; the gateway's environment has neither.
				gatewayEnvironment := os.Environ()
				provenanceGatewayEnvironment = func(int, string) ([]string, error) { return gatewayEnvironment, nil }
				t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "token of the edited data_dir")
				cfg = provenanceTestConfig(t, server)
				cfg.Gateway.Token, cfg.Gateway.TokenEnv = "", ""
				cfg.DataDir = edited
			}
			if err := runProvenanceShow(cmd, nil); err != nil || !strings.Contains(out.String(), "generation: 61\n") {
				t.Fatalf("output=%q error=%v", out, err)
			}
			if gateway.requests.Load() == before {
				t.Fatal("the gateway was not asked")
			}
		})
	}
	// Without the record (a gateway of an earlier release), the default data
	// directory is all there is: B's answer is refused as another home's.
	if err := os.Remove(filepath.Join(home, daemon.AppliedAuthFileName)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", provenanceTestToken)
	provenanceGatewayEnvironment = func(int, string) ([]string, error) { return os.Environ(), nil }
	cfg = provenanceTestConfig(t, server)
	cfg.DataDir = config.DefaultDataPath()
	cmd, out, _ := provenanceTestCommand()
	if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "another DefenseClaw home") || out.Len() != 0 {
		t.Fatalf("no record: output=%q error=%v", out, err)
	}
}
