// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// gatewayProofHelperEnv makes this test binary a long-running stand-in for
// a gateway process (TestProveOwnGatewayHelperProcess).
const gatewayProofHelperEnv = "DEFENSECLAW_TEST_GATEWAY_PROOF_HELPER"

// TestProveOwnGatewayHelperProcess is the stand-in gateway: this binary,
// running as this account with the environment its parent gave it.
func TestProveOwnGatewayHelperProcess(*testing.T) {
	if os.Getenv(gatewayProofHelperEnv) != "1" {
		return
	}
	time.Sleep(time.Minute)
	os.Exit(0)
}

// gatewayEnvironment is this process's environment without the daemon
// variables, plus extra: the environment of a process the test starts.
func gatewayEnvironment(extra ...string) []string {
	var environment []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if environmentKeyIs(key, EnvDaemon) || environmentKeyIs(key, EnvDataDir) {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, extra...)
}

// startThisBinary starts this test binary as a stand-in gateway with the
// daemon variables extra; Daemon.Start gives its gateway EnvDaemon=1 and
// EnvDataDir=<home>.
func startThisBinary(t *testing.T, extra ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProveOwnGatewayHelperProcess$")
	cmd.Env = gatewayEnvironment(append([]string{gatewayProofHelperEnv + "=1"}, extra...)...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// otherProgramOfThisAccount starts a long-running program that is not this
// binary, as this account, with the environment of a gateway of home.
func otherProgramOfThisAccount(t *testing.T, home string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if runtime.GOOS == "windows" {
		cmd = exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"), "-n", "60", "127.0.0.1")
	}
	cmd.Env = gatewayEnvironment(EnvDaemon+"=1", EnvDataDir+"="+home)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// The gateway credential goes only to a process the operating system shows
// is this home's gateway of this account now: it runs as this account, from
// this DefenseClaw binary, with the environment Daemon.Start gives the
// gateway of this home. No record is read, so no record makes another
// program, another account's process, a process that has exited, or the
// gateway of another home of this account, this home's gateway. Before, the
// gateway of another home (same account, same binary) was proven, and a
// rejected config.yaml in this home sent it this home's token.
func TestProveOwnGatewayNeedsThisAccountThisBinaryAndThisHomeNow(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("gateway processes cannot be proven on %s", runtime.GOOS)
	}
	home := t.TempDir()
	gateway := startThisBinary(t, EnvDaemon+"=1", EnvDataDir+"="+home)
	pid := gateway.Process.Pid
	identity, err := ProveOwnGateway(pid, home)
	if err != nil || identity == "" {
		t.Fatalf("this home's gateway: identity=%q err=%v", identity, err)
	}
	if live, err := processStartIdentity(pid); err != nil || live != identity {
		t.Fatalf("returned start identity %q, live %q (%v)", identity, live, err)
	}
	if _, err := ProveOwnGateway(pid, home+string(filepath.Separator)); err != nil {
		t.Fatalf("this home spelled with a trailing separator: %v", err)
	}

	// The gateway of another home of this account: same account, same
	// binary, and still not this home's.
	other := t.TempDir()
	if _, err := ProveOwnGateway(pid, other); !errors.Is(err, ErrGatewayNotVerified) ||
		!strings.Contains(err.Error(), "another DefenseClaw home") {
		t.Fatalf("another home's gateway: %v", err)
	}
	for name, extra := range map[string][]string{
		"no daemon marker":        {EnvDataDir + "=" + home},
		"another daemon marker":   {EnvDaemon + "=0", EnvDataDir + "=" + home},
		"no data directory":       {EnvDaemon + "=1"},
		"an empty data directory": {EnvDaemon + "=1", EnvDataDir + "="},
	} {
		started := startThisBinary(t, extra...)
		if _, err := ProveOwnGateway(started.Process.Pid, home); !errors.Is(err, ErrGatewayNotVerified) ||
			!strings.Contains(err.Error(), "not started by `defenseclaw-gateway start`") {
			t.Fatalf("this binary with %s: %v", name, err)
		}
	}
	if _, err := ProveOwnGateway(pid, ""); !errors.Is(err, ErrGatewayNotVerified) {
		t.Fatalf("no home: %v", err)
	}
	// A relative home is a directory only with a working directory, and the
	// gateway's need not be this one's: never proven, even spelled the same.
	relative := startThisBinary(t, EnvDaemon+"=1", EnvDataDir+"=relative-home")
	for _, asked := range []string{"relative-home", home} {
		if _, err := ProveOwnGateway(relative.Process.Pid, asked); !errors.Is(err, ErrGatewayNotVerified) ||
			!strings.Contains(err.Error(), "relative DefenseClaw home") {
			t.Fatalf("a gateway of the relative home, asked for %q: %v", asked, err)
		}
	}
	if _, err := ProveOwnGateway(pid, "relative-home"); !errors.Is(err, ErrGatewayNotVerified) {
		t.Fatalf("this gateway asked for a relative home: %v", err)
	}

	program := otherProgramOfThisAccount(t, home)
	programPID := program.Process.Pid
	if runtime.GOOS == "linux" {
		// The strongest record there is, bound to this home and naming the
		// other program with its executable and start identity, changes
		// nothing.
		executable, err := processExecutable(programPID)
		if err != nil {
			t.Fatal(err)
		}
		startIdentity, err := processStartIdentity(programPID)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(pidInfo{PID: programPID, Executable: executable, DataDir: home,
			StartTime: time.Now().Unix(), StartIdentity: startIdentity})
		if err != nil {
			t.Fatal(err)
		}
		if err := safefile.WritePrivate(filepath.Join(home, PIDFileName), raw); err != nil {
			t.Fatal(err)
		}
		if !New(home).HasManagedProcessIdentity(programPID) {
			t.Fatal("precondition: this home's current PID record must name the other program")
		}
	}
	// The gateway's environment does not make another program the gateway.
	if _, err := ProveOwnGateway(programPID, home); !errors.Is(err, ErrGatewayNotVerified) ||
		!strings.Contains(err.Error(), "not this DefenseClaw binary") {
		t.Fatalf("another program of this account: %v", err)
	}

	foreign := 1
	if runtime.GOOS == "windows" {
		foreign = 4 // System
	}
	if _, err := ProveOwnGateway(foreign, home); !errors.Is(err, ErrGatewayNotVerified) {
		t.Fatalf("PID %d: %v", foreign, err)
	}
	switch {
	case runtime.GOOS == "windows":
		if err := processRunsAsCaller(foreign); err == nil {
			t.Fatal("the System process runs as this account")
		}
	case os.Geteuid() != 0:
		if err := processRunsAsCaller(foreign); !errors.Is(err, errProcessOfAnotherAccount) {
			t.Fatalf("PID 1 of root runs as this account: %v", err)
		}
		// Another account's PID is not this account's to see.
		if _, err := ProveOwnGateway(foreign, home); err == nil || !strings.Contains(err.Error(), "runs as another account") ||
			strings.Contains(err.Error(), "PID 1") {
			t.Fatalf("another account's process: %v", err)
		}
	}

	_ = gateway.Process.Kill()
	_ = gateway.Wait()
	for _, gone := range []int{pid, 0, -1} {
		if _, err := ProveOwnGateway(gone, home); !errors.Is(err, ErrGatewayNotVerified) {
			t.Fatalf("PID %d: %v", gone, err)
		}
	}
}

// kern.procargs2 (macOS) holds the argument count, the executable path and
// its padding, the arguments, then the environment up to an empty string.
// Only the environment is returned, and a malformed record is an error.
func TestProcArgs2EnvironmentReadsOnlyTheEnvironment(t *testing.T) {
	record := func(argc uint32, body string) []byte {
		data := binary.LittleEndian.AppendUint32(nil, argc)
		return append(data, body...)
	}
	got, err := procArgs2Environment(record(2,
		"/opt/defenseclaw/defenseclaw-gateway\x00\x00\x00\x00defenseclaw-gateway\x00"+EnvDataDir+"=/not/the/environment\x00"+
			"HOME=/Users/u\x00"+EnvDaemon+"=1\x00"+EnvDataDir+"=/Users/u/.defenseclaw\x00\x00executable_path=/x\x00"))
	want := []string{"HOME=/Users/u", EnvDaemon + "=1", EnvDataDir + "=/Users/u/.defenseclaw"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("environment = %q, %v; want %q", got, err, want)
	}
	// A last string the record cut is not part of it.
	got, err = procArgs2Environment(record(1, "/x\x00x\x00A=1\x00"+EnvDataDir+"=/cut"))
	if err != nil || !reflect.DeepEqual(got, []string{"A=1"}) {
		t.Fatalf("cut environment = %q, %v", got, err)
	}
	for name, data := range map[string][]byte{
		"too short":           {1, 0},
		"no arguments":        record(0, "/x\x00"),
		"truncated arguments": record(3, "/x\x00a\x00b"),
		"no executable end":   record(1, "/x"),
	} {
		if _, err := procArgs2Environment(data); err == nil {
			t.Fatalf("%s: parsed", name)
		}
	}
}
