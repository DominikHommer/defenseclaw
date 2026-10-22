// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A scanner run that did not end with the scanner's own exit status is a
// failed scan, even when the scanner had already written clean JSON. On macOS
// a helper outside the scanner's process group that keeps stdout or stderr
// open makes RunTree return exec.ErrWaitDelay after a clean exit; the skill,
// plugin and MCP scans took that output as a clean scan (W4b2 loop round 2).
func TestScannersFailARunThatDidNotFinish(t *testing.T) {
	prior := runScannerCommand
	t.Cleanup(func() { runScannerCommand = prior })
	bin := filepath.Join(t.TempDir(), "scanner-fixture")
	scanners := []struct {
		name    string
		scanner Scanner
	}{
		{"skill", NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: bin}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})},
		{"plugin", &PluginScanner{BinaryPath: bin}},
		{"mcp", NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: bin}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})},
	}
	runErrors := []error{
		exec.ErrWaitDelay,
		context.DeadlineExceeded,
		context.Canceled,
		fmt.Errorf("processutil: release scanner start gate: %w", errors.New("broken pipe")),
		errors.New("kevent: bad file descriptor"),
	}
	for _, tc := range scanners {
		for _, runErr := range runErrors {
			t.Run(tc.name+"/"+runErr.Error(), func(t *testing.T) {
				runScannerCommand = func(cmd *exec.Cmd) error {
					_, _ = io.WriteString(cmd.Stdout, `{"findings":[]}`+"\n")
					return runErr
				}
				result, err := tc.scanner.Scan(context.Background(), t.TempDir())
				if !errors.Is(err, runErr) {
					t.Fatalf("Scan error = %v, want it to wrap %v (result=%+v)", err, runErr, result)
				}
				if result != nil {
					t.Fatalf("Scan returned a result %+v for a run that did not finish", result)
				}
			})
		}
		// Control: the same output with the scanner's clean exit is a clean
		// scan, so the failures above come from the run error alone.
		t.Run(tc.name+"/clean exit", func(t *testing.T) {
			runScannerCommand = func(cmd *exec.Cmd) error {
				_, _ = io.WriteString(cmd.Stdout, `{"findings":[]}`+"\n")
				return nil
			}
			result, err := tc.scanner.Scan(context.Background(), t.TempDir())
			if err != nil || result == nil || result.ExitCode != 0 || len(result.Findings) != 0 {
				t.Fatalf("clean scan = %+v, %v; want a clean result", result, err)
			}
		})
	}
}
