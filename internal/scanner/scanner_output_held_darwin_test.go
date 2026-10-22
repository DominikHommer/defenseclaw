//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
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

const darwinOutputHolderEnv = "DC_SCANNER_DARWIN_OUTPUT_HOLDER"

// TestDarwinScannerOutputHolderHelper is the detached helper of
// TestDarwinScannerOutputHeldOpenFailsScan: it leaves the scanner's process
// group and keeps the inherited stdout and stderr open.
func TestDarwinScannerOutputHolderHelper(t *testing.T) {
	pidFile := os.Getenv(darwinOutputHolderEnv)
	if pidFile == "" {
		t.Skip("helper for TestDarwinScannerOutputHeldOpenFailsScan")
	}
	if err := syscall.Setpgid(0, 0); err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		os.Exit(2)
	}
	time.Sleep(60 * time.Second)
	os.Exit(0)
}

// Native macOS: a scanner prints clean JSON and exits 0 while a helper in
// another process group holds its output open. RunTree's wait for the output
// ends with exec.ErrWaitDelay; the scan must fail, not admit the clean JSON.
func TestDarwinScannerOutputHeldOpenFailsScan(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"skill", "plugin", "mcp"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "holder.pid")
			bin := filepath.Join(dir, "defenseclaw")
			script := "#!/bin/sh\n" +
				darwinOutputHolderEnv + "='" + pidFile + "' '" + self + "' -test.run='^TestDarwinScannerOutputHolderHelper$' -test.count=1 &\n" +
				"n=0; while [ ! -s '" + pidFile + "' ] && [ $n -lt 200 ]; do sleep 0.05; n=$((n+1)); done\n" +
				"printf '%s\\n' '{\"findings\":[]}'\nexit 0\n"
			if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { killDarwinOutputHolder(pidFile) })
			var scanner Scanner
			switch name {
			case "skill":
				scanner = NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: bin}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
			case "plugin":
				scanner = &PluginScanner{BinaryPath: bin}
			default:
				scanner = NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: bin}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
			}
			start := time.Now()
			result, err := scanner.Scan(context.Background(), dir)
			if !errors.Is(err, exec.ErrWaitDelay) || result != nil {
				t.Fatalf("Scan = %+v, %v; want a failed scan wrapping exec.ErrWaitDelay", result, err)
			}
			if elapsed := time.Since(start); elapsed > 30*time.Second {
				t.Fatalf("Scan took %s with its output held open", elapsed)
			}
			if data, readErr := os.ReadFile(pidFile); readErr != nil || strings.TrimSpace(string(data)) == "" {
				t.Fatalf("the detached helper never held the output (%v)", readErr)
			}
		})
	}
}

func killDarwinOutputHolder(pidFile string) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}
