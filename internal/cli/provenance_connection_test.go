// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// provenanceAcceptorEnv makes this test binary a process of this account
// that accepts one connection on a loopback port, closes its listener and
// reads that connection (TestProvenanceAcceptorHelperProcess).
const provenanceAcceptorEnv = "DEFENSECLAW_TEST_PROVENANCE_ACCEPTOR_DIR"

// TestProvenanceAcceptorHelperProcess is the other process: it publishes
// its port, accepts one connection, frees the port, and marks every HTTP
// request it reads on that connection, "credentialed" when it carried an
// Authorization header.
func TestProvenanceAcceptorHelperProcess(*testing.T) {
	dir := os.Getenv(provenanceAcceptorEnv)
	if dir == "" {
		return
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if os.WriteFile(filepath.Join(dir, "port.tmp"), []byte(port), 0o600) != nil ||
		os.Rename(filepath.Join(dir, "port.tmp"), filepath.Join(dir, "port")) != nil {
		os.Exit(3)
	}
	conn, err := listener.Accept()
	if err != nil {
		os.Exit(4)
	}
	_ = listener.Close() // the port is free; this process keeps the connection
	_ = os.WriteFile(filepath.Join(dir, "accepted"), nil, 0o600)
	reader := bufio.NewReader(conn)
	for {
		request, err := http.ReadRequest(reader)
		if err != nil {
			os.Exit(0)
		}
		name := "request"
		if request.Header.Get("Authorization") != "" {
			name = "credentialed"
		}
		_ = os.WriteFile(filepath.Join(dir, name), nil, 0o600)
		_, _ = io.WriteString(conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
	}
}

// waitForProvenanceFile waits for path to exist.
func waitForProvenanceFile(path string) error {
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New(path + " did not appear")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The finding: during an API listener restart another process of this
// computer binds the port and accepts the provenance connection, then
// closes its listener, and the gateway binds the port again while that
// connection stays open. The listener inspected after connecting is the
// gateway's, so the token went on the connection the other process
// accepted and reads. Now the server end of the connection itself must be
// the gateway's: that process gets no request and no token. The listener
// inspection here is the real one where this platform lets the gateway bind
// the port again under the open connection.
func TestProvenanceShowSendsNoTokenOnAConnectionAnotherProcessAccepted(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("connections cannot be inspected on %s", runtime.GOOS)
	}
	isolateProvenanceHome(t)
	dir := t.TempDir()
	helper := exec.Command(os.Args[0], "-test.run=^TestProvenanceAcceptorHelperProcess$")
	helper.Env = append(os.Environ(), provenanceAcceptorEnv+"="+dir)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	if err := waitForProvenanceFile(filepath.Join(dir, "port")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "port"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu      sync.Mutex
		rebound []net.Listener
	)
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, listener := range rebound {
			_ = listener.Close()
		}
	})
	stubProvenanceGateway(t, provenanceGateway{PID: os.Getpid()}, func(host string, port int) ([]daemon.PortHolder, error) {
		// The other process has accepted and freed the port; the gateway
		// (this process) binds it again before the listener is inspected.
		if err := waitForProvenanceFile(filepath.Join(dir, "accepted")); err != nil {
			return nil, err
		}
		if listener, err := net.Listen("tcp4", net.JoinHostPort(host, strconv.Itoa(port))); err == nil {
			mu.Lock()
			rebound = append(rebound, listener)
			mu.Unlock()
			return daemon.FindPortHolders(host, port)
		}
		return []daemon.PortHolder{{PID: os.Getpid()}}, nil
	})
	provenanceConnectionHolders = daemon.FindConnectionHolders
	cfg = provenanceTestConfigAt("127.0.0.1", port)
	cmd, out, _ := provenanceTestCommand()
	err = runProvenanceShow(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "gateway not verified") ||
		!strings.Contains(err.Error(), "the gateway token was not sent") || out.Len() != 0 {
		t.Fatalf("a connection another process accepted: output=%q error=%v", out, err)
	}
	for _, name := range []string{"credentialed", "request"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("the process that accepted the connection got a %s", name)
		}
	}
}

// Who holds the server end of a connection decides, for every answer the
// operating system can give: only the gateway is the gateway; a connection
// that still waits for the gateway to accept it is waited for, briefly;
// another process, a process this account cannot see, a connection shared
// with another process, a connection that is gone or cannot be inspected is
// not proven.
func TestProvenanceConnectionAcceptedByOnlyTheGateway(t *testing.T) {
	stubProvenanceSeams(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	gateway := provenanceGateway{PID: 4242}
	queued := func(n int, then []daemon.PortHolder) func(netip.AddrPort, netip.AddrPort) ([]daemon.PortHolder, error) {
		calls := 0
		return func(server, client netip.AddrPort) ([]daemon.PortHolder, error) {
			if server != conn.RemoteAddr().(*net.TCPAddr).AddrPort() || client != conn.LocalAddr().(*net.TCPAddr).AddrPort() {
				return nil, errors.New("asked about another socket")
			}
			calls++
			if calls <= n {
				return nil, daemon.ErrNoConnection
			}
			return then, nil
		}
	}
	for _, tc := range []struct {
		name    string
		holders func(netip.AddrPort, netip.AddrPort) ([]daemon.PortHolder, error)
		want    bool
	}{
		{"the gateway", queued(0, []daemon.PortHolder{{PID: 4242}}), true},
		{"the gateway, after the listen queue", queued(5, []daemon.PortHolder{{PID: 4242}}), true},
		{"another process", queued(0, []daemon.PortHolder{{PID: 4243}}), false},
		{"another process, after the listen queue", queued(3, []daemon.PortHolder{{PID: 4243}}), false},
		{"the gateway and another process", queued(0, []daemon.PortHolder{{PID: 4242}, {PID: 4243}}), false},
		{"a process this account cannot see", queued(0, []daemon.PortHolder{{PID: 0, UID: -1}}), false},
		{"never accepted", queued(1<<30, nil), false},
		{"no holder listed", queued(0, nil), false},
		{"inspection unavailable", func(netip.AddrPort, netip.AddrPort) ([]daemon.PortHolder, error) {
			return nil, daemon.ErrListenerInspectionUnavailable
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provenanceConnectionHolders = tc.holders
			started := time.Now()
			if got := provenanceConnectionAcceptedBy(context.Background(), conn, gateway); got != tc.want {
				t.Fatalf("accepted by the gateway = %v, want %v", got, tc.want)
			}
			if elapsed := time.Since(started); elapsed > 3*provenanceAcceptWait {
				t.Fatalf("took %v", elapsed)
			}
		})
	}
	// A cancelled read does not wait.
	provenanceConnectionHolders = queued(1<<30, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if provenanceConnectionAcceptedBy(ctx, conn, gateway) {
		t.Fatal("a cancelled read proved a connection")
	}
	if provenanceConnectionAcceptedBy(context.Background(), conn, provenanceGateway{}) {
		t.Fatal("no gateway process proved a connection")
	}
}

// The finding: the shell running provenance holds a stale
// DEFENSECLAW_GATEWAY_TOKEN and the home's .env the gateway's. Daemon.Start
// gave the gateway the .env token in place of the shell's, but provenance
// read the shell first and got HTTP 401. Now the token resolves from the
// gateway process's own environment, which the operating system shows, so
// every way the gateway's token differs from this shell's is read right: a
// stale shell token with or without the gateway's credential record, the
// legacy variable in .env, a stale variable in another letter case (one
// variable on Windows), a custom token_env the gateway took from the shell
// that started it (not from .env), and a gateway started from another shell.
func TestProvenanceShowSendsTheTokenOfTheGatewaysOwnEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("gateway processes cannot be proven on %s", runtime.GOOS)
	}
	home := isolateProvenanceHome(t)
	stubProvenanceSeams(t)
	provenanceGatewayEnvironment = daemon.GatewayEnvironment
	const stale = "stale token of this shell"
	tokenNames := []string{"DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN", "R104_GATEWAY_TOKEN"}
	// shellWith is this process's environment without any gateway token,
	// plus vars: the shell `defenseclaw-gateway start` ran in.
	shellWith := func(vars map[string]string) []string {
		var shell []string
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			isToken := false
			for _, name := range tokenNames {
				isToken = isToken || strings.EqualFold(key, name)
			}
			if !isToken {
				shell = append(shell, entry)
			}
		}
		for key, value := range vars {
			shell = append(shell, key+"="+value)
		}
		return shell
	}
	for _, tc := range []struct {
		name     string
		dotenv   string            // the home's .env
		launched map[string]string // the shell that started the gateway
		shell    map[string]string // the shell running provenance
		tokenEnv string            // the gateway's credential record; "-" none
	}{
		{"stale shell token, home .env token", "DEFENSECLAW_GATEWAY_TOKEN=" + provenanceTestToken,
			map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": stale}, map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": stale}, "-"},
		{"stale shell token, home .env token, recorded", "DEFENSECLAW_GATEWAY_TOKEN=" + provenanceTestToken,
			map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": stale}, map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": stale}, ""},
		{"stale shell token, legacy .env token", "OPENCLAW_GATEWAY_TOKEN=" + provenanceTestToken,
			map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": stale}, map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": stale}, "-"},
		{"stale shell token in another case", "DEFENSECLAW_GATEWAY_TOKEN=" + provenanceTestToken,
			map[string]string{"defenseclaw_gateway_token": stale}, map[string]string{"defenseclaw_gateway_token": stale}, ""},
		{"custom token_env of the starting shell", "R104_GATEWAY_TOKEN=token of the .env the shell overrides",
			map[string]string{"R104_GATEWAY_TOKEN": provenanceTestToken}, map[string]string{"R104_GATEWAY_TOKEN": stale}, "R104_GATEWAY_TOKEN"},
		{"started from another shell", "",
			map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": provenanceTestToken}, map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": stale}, "-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envPath := filepath.Join(home, ".env")
			_ = os.Remove(envPath)
			_ = os.Remove(filepath.Join(home, daemon.AppliedAuthFileName))
			if tc.dotenv != "" {
				if err := os.WriteFile(envPath, []byte(tc.dotenv+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			pid := startProvenanceTestGatewayFrom(t, home, shellWith(tc.launched))
			identity, err := daemon.ProveOwnGateway(pid, home)
			if err != nil {
				t.Fatalf("precondition: the stand-in gateway is this home's: %v", err)
			}
			if tc.tokenEnv != "-" {
				record := `{"pid":` + strconv.Itoa(pid) + `,"start_identity":` + strconv.Quote(identity) +
					`,"token_env":` + strconv.Quote(tc.tokenEnv) + `}`
				if err := os.WriteFile(filepath.Join(home, daemon.AppliedAuthFileName), []byte(record), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, ok := daemon.New(home).AppliedAuth(pid); !ok {
					t.Fatal("precondition: the credential record names the stand-in gateway")
				}
			}
			for key, value := range tc.shell {
				t.Setenv(key, value)
			}
			gateway := newProvenanceTestGateway()
			gateway.live.Generation = 71
			server := serveProvenanceTestGateway(t, gateway, pid)
			cfg = provenanceTestConfig(t, server)
			cfg.Gateway.Token, cfg.Gateway.TokenEnv, cfg.DataDir = "", "", home
			cmd, out, _ := provenanceTestCommand()
			if err := runProvenanceShow(cmd, nil); err != nil || !strings.Contains(out.String(), "generation: 71\n") {
				t.Fatalf("output=%q error=%v", out, err)
			}
			if gateway.credentialed.Load() != 1 {
				t.Fatalf("%d requests carried a credential, want the gateway's one", gateway.credentialed.Load())
			}
		})
	}
	// A gateway whose environment cannot be read for the proven process gets
	// no token: the read is refused before anything is sent.
	provenanceGatewayEnvironment = func(int, string) ([]string, error) {
		return nil, errors.New("the environment is unreadable")
	}
	gateway := newProvenanceTestGateway()
	pid := startProvenanceTestGatewayFrom(t, home, shellWith(nil))
	cfg = provenanceTestConfig(t, serveProvenanceTestGateway(t, gateway, pid))
	cfg.Gateway.Token = provenanceTestToken
	cmd, out, _ := provenanceTestCommand()
	if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "the gateway token was not sent") ||
		out.Len() != 0 || gateway.requests.Load() != 0 {
		t.Fatalf("unreadable environment: output=%q error=%v requests=%d", out, err, gateway.requests.Load())
	}
}
