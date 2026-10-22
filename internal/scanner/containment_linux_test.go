// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func scannerDetachedFixture(t *testing.T, pidFile string) string {
	t.Helper()
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	path := filepath.Join(t.TempDir(), "scanner-fixture")
	script := "#!/bin/sh\npidfile='" + strings.ReplaceAll(pidFile, "'", "'\\''") + "'\n" + `setsid sh -c 'echo $$ > "$1"; exec sleep 60' sh "$pidfile" </dev/null >/dev/null 2>&1 &
while [ ! -s "$pidfile" ]; do sleep 0.01; done
if [ "${DC_SCANNER_TEST_WAIT:-}" = 1 ]; then sleep 60; fi
printf '{"findings":[]}\n'
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func scannerFixturePID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil {
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if convErr == nil && pid > 0 {
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("detached scanner child never wrote %s", path)
	return 0
}

func scannerFixtureRunning(pid int) bool {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return false
	}
	fields := strings.Fields(string(raw[end+1:]))
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

func scannerFixtureGone(pid int) bool {
	deadline := time.Now().Add(3 * time.Second)
	for scannerFixtureRunning(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	return !scannerFixtureRunning(pid)
}

// Plugin, skill, and MCP scans must own children that leave their process
// group and close inherited streams. The old RunTree path returned a clean
// scan while the child kept running.
func TestScannersContainDetachedChildren(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func(string) Scanner
	}{
		{"plugin", func(fixture string) Scanner { return NewPluginScanner(fixture) }},
		{"skill", func(fixture string) Scanner {
			return NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: fixture}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
		}},
		{"mcp", func(fixture string) Scanner {
			return NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: fixture}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "detached.pid")
			fixture := scannerDetachedFixture(t, pidFile)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := tc.new(fixture).Scan(ctx, t.TempDir())
			pid := scannerFixturePID(t, pidFile)
			if !scannerFixtureGone(pid) {
				t.Fatalf("Scan() = %+v, %v; detached scanner child %d is still running", result, err, pid)
			}
			if err != nil {
				t.Fatalf("contained scan failed: %v", err)
			}
		})
	}
}

// An ungraceful gateway exit does not run its Go cleanup. The scanner's
// custodian must still end a detached child that closed all inherited pipes.
func TestScannerDetachedChildDiesWithGateway(t *testing.T) {
	if os.Getenv("DC_SCANNER_TEST_GATEWAY") == "1" {
		_, _ = NewPluginScanner(os.Getenv("DC_SCANNER_TEST_FIXTURE")).Scan(context.Background(), "local")
		return
	}
	pidFile := filepath.Join(t.TempDir(), "detached.pid")
	fixture := scannerDetachedFixture(t, pidFile)
	gateway := exec.Command(os.Args[0], "-test.run=^TestScannerDetachedChildDiesWithGateway$")
	gateway.Env = append(os.Environ(),
		"DC_SCANNER_TEST_GATEWAY=1", "DC_SCANNER_TEST_FIXTURE="+fixture,
		"DC_SCANNER_TEST_WAIT=1")
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })
	pid := scannerFixturePID(t, pidFile)
	if err := gateway.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = gateway.Wait()
	if !scannerFixtureGone(pid) {
		t.Fatalf("detached scanner child %d survived gateway death", pid)
	}
}
