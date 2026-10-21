// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// GAP-0143: hooks that find the account's gateway down at the same time
// launch one background start, not one each. A lock left by a start that
// ended (15 s or more old) does not stop the next restart's start.
func TestConcurrentHooksLaunchOneGatewayColdStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks start the gateway through hookexec")
	}
	shell := systemBashForTest(t)
	helperPath := materializeHookAssetForTest(t, "hooks/_hardening.sh")
	home := t.TempDir()
	data := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "config.yaml"), []byte("gateway: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	starts := filepath.Join(home, "starts")
	binary := filepath.Join(home, ".local", "bin", "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho \"$*\" >> "+starts+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	coldStart := func() {
		command := exec.Command(shell, "-c", `source "$0"; defenseclaw_gateway_cold_start`, helperPath)
		command.Env = append(os.Environ(), "DEFENSECLAW_AGENT_HOME="+home, "HOME="+home, "DEFENSECLAW_HOME="+data)
		if out, err := command.CombinedOutput(); err != nil {
			t.Errorf("cold start: %v\n%s", err, out)
		}
	}
	launched := func() int {
		deadline := time.Now().Add(2 * time.Second)
		for {
			body, _ := os.ReadFile(starts)
			n := strings.Count(string(body), "start --hook-cold-start")
			if n > 0 || time.Now().After(deadline) {
				time.Sleep(200 * time.Millisecond) // a second start would have written by now
				body, _ = os.ReadFile(starts)
				return strings.Count(string(body), "start --hook-cold-start")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			coldStart()
		}()
	}
	wg.Wait()
	if n := launched(); n != 1 {
		t.Fatalf("4 hooks at once launched %d gateway starts, want 1", n)
	}
	old := strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
	if err := os.WriteFile(filepath.Join(data, ".cold-start.lock"), []byte(old+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	coldStart()
	if n := launched(); n != 2 {
		t.Fatalf("after a start that ended, the next restart launched %d starts in all, want 2", n)
	}
}
