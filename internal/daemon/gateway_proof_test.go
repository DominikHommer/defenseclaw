// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// otherProgramOfThisAccount starts a long-running program that is not this
// binary, as this account.
func otherProgramOfThisAccount(t *testing.T) *exec.Cmd {
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

// The gateway credential goes only to a process the operating system shows
// is a gateway of this account now: it runs as this account and from this
// DefenseClaw binary. No record is read, so no record makes another program,
// another account's process, or a process that has exited, the gateway.
// Before, a PID record bound to this home named whatever process it was
// written for (on Windows another account's gateway, whose image path and
// start time any account may read).
func TestProveOwnGatewayNeedsThisAccountAndThisBinaryNow(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("gateway processes cannot be proven on %s", runtime.GOOS)
	}
	identity, err := ProveOwnGateway(os.Getpid())
	if err != nil || identity == "" {
		t.Fatalf("this binary's own process of this account: identity=%q err=%v", identity, err)
	}
	if live, err := processStartIdentity(os.Getpid()); err != nil || live != identity {
		t.Fatalf("returned start identity %q, live %q (%v)", identity, live, err)
	}

	other := otherProgramOfThisAccount(t)
	otherPID := other.Process.Pid
	if runtime.GOOS == "linux" {
		// The strongest record there is, bound to this home and naming the
		// other program with its executable and start identity, changes
		// nothing.
		home := t.TempDir()
		executable, err := processExecutable(otherPID)
		if err != nil {
			t.Fatal(err)
		}
		startIdentity, err := processStartIdentity(otherPID)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(pidInfo{PID: otherPID, Executable: executable, DataDir: home,
			StartTime: time.Now().Unix(), StartIdentity: startIdentity})
		if err != nil {
			t.Fatal(err)
		}
		if err := safefile.WritePrivate(filepath.Join(home, PIDFileName), raw); err != nil {
			t.Fatal(err)
		}
		if !New(home).HasManagedProcessIdentity(otherPID) {
			t.Fatal("precondition: this home's current PID record must name the other program")
		}
	}
	if _, err := ProveOwnGateway(otherPID); !errors.Is(err, ErrGatewayNotVerified) ||
		!strings.Contains(err.Error(), "not this DefenseClaw binary") {
		t.Fatalf("another program of this account: %v", err)
	}

	foreign := 1
	if runtime.GOOS == "windows" {
		foreign = 4 // System
	}
	if _, err := ProveOwnGateway(foreign); !errors.Is(err, ErrGatewayNotVerified) {
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
		if _, err := ProveOwnGateway(foreign); err == nil || !strings.Contains(err.Error(), "runs as another account") ||
			strings.Contains(err.Error(), "PID 1") {
			t.Fatalf("another account's process: %v", err)
		}
	}

	_ = other.Process.Kill()
	_ = other.Wait()
	for _, pid := range []int{otherPID, 0, -1} {
		if _, err := ProveOwnGateway(pid); !errors.Is(err, ErrGatewayNotVerified) {
			t.Fatalf("PID %d: %v", pid, err)
		}
	}
}
