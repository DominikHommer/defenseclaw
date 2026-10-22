// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

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

// A scanner that calls setsid and closes every inherited descriptor escaped
// the previous process group and lifeline. macOS has no subreaper; scanner
// execution must fail closed before such a child can be born.
func TestScannersCannotDetachChildOnDarwin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("RLIMIT_NPROC cannot confine a root scanner")
	}
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl is not installed")
	}
	for _, tc := range []struct {
		name string
		new  func(string) Scanner
	}{
		{"plugin", func(path string) Scanner { return NewPluginScanner(path) }},
		{"skill", func(path string) Scanner {
			return NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: path}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
		}},
		{"mcp", func(path string) Scanner {
			return NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: path}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "detached.pid")
			quoted := "'" + strings.ReplaceAll(pidFile, "'", "'\\''") + "'"
			fixture := filepath.Join(t.TempDir(), "scanner-fixture")
			script := "#!/bin/bash\npidfile=" + quoted + "\n" + `perl -MPOSIX -e 'POSIX::setsid() >= 0 or die; exec @ARGV or die' /bin/bash -c 'echo $$ > "$1"; exec sleep 60' sh "$pidfile" </dev/null >/dev/null 2>&1 &
end=$((SECONDS+2))
while [ ! -s "$pidfile" ] && [ "$SECONDS" -lt "$end" ]; do :; done
if [ ! -s "$pidfile" ]; then printf 'fork refused\n' >&2; exit 9; fi
printf '{"findings":[]}\n'
`
			if err := os.WriteFile(fixture, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := tc.new(fixture).Scan(ctx, t.TempDir())
			if raw, readErr := os.ReadFile(pidFile); readErr == nil {
				pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
				if pid > 0 {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
				t.Fatalf("Scan() = %+v, %v; detached scanner child %d was started", result, err, pid)
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("inspect detached scanner child: %v", readErr)
			}
			if err == nil {
				t.Fatalf("Scan() = %+v, nil; rejected scanner fork must fail closed", result)
			}
		})
	}
}

func TestScannersRunForkFreeOnDarwin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("RLIMIT_NPROC cannot confine a root scanner")
	}
	fixture := buildScannerFixture(t, `{"findings":[]}`+"\n", 0)
	for _, tc := range []struct {
		name string
		scan Scanner
	}{
		{"plugin", NewPluginScanner(fixture)},
		{"skill", NewSkillScannerFromLLM(config.SkillScannerConfig{Binary: fixture}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})},
		{"mcp", NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: fixture}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.scan.Scan(context.Background(), t.TempDir())
			if err != nil || result == nil || len(result.Findings) != 0 {
				t.Fatalf("Scan() = %+v, %v; want a clean fork-free scan", result, err)
			}
		})
	}
}
