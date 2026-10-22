// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestHermesRegistrationRequiresExecutableProbe(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	opts := SetupOpts{DataDir: filepath.Join(root, "dc")}
	script := filepath.Join(opts.DataDir, "hooks", "hermes-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'defenseclaw-execution-probe-ok\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesHooks(configPath, script, ""); err != nil {
		t.Fatal(err)
	}
	conn := NewHermesConnector()
	if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
		t.Fatalf("executable registration present=%v err=%v", present, err)
	}
	if err := os.Chmod(script, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("non-executable registration present=%v err=%v, want absent", present, err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("early success without runtime proof present=%v err=%v, want absent", present, err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("failed execution probe present=%v err=%v, want absent", present, err)
	}
}

func writeHermesProbeScript(t *testing.T, body string) string {
	t.Helper()
	script := filepath.Join(testenv.PrivateTempDir(t), "hermes-hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script
}

func setHermesExecutionProbeBounds(t *testing.T, timeout, pipeWait time.Duration) {
	t.Helper()
	previousTimeout, previousPipeWait := hermesExecutionProbeTimeout, hermesExecutionProbePipeWait
	hermesExecutionProbeTimeout, hermesExecutionProbePipeWait = timeout, pipeWait
	t.Cleanup(func() {
		hermesExecutionProbeTimeout, hermesExecutionProbePipeWait = previousTimeout, previousPipeWait
	})
}

// A registered hook that writes far more than the proof must neither grow
// Verify's memory with its output nor keep Verify running until the timeout.
func TestHermesExecutionProbeCapsCapturedOutput(t *testing.T) {
	setHermesExecutionProbeBounds(t, 20*time.Second, time.Second)
	for name, body := range map[string]string{
		"proof then 64 MiB": "printf 'defenseclaw-execution-probe-ok\\n'\nhead -c 67108864 /dev/zero\n",
		"64 MiB then proof": "head -c 67108864 /dev/zero\nprintf 'defenseclaw-execution-probe-ok\\n'\n",
		"endless stream":    "printf 'defenseclaw-execution-probe-ok\\n'\nexec yes\n",
	} {
		t.Run(name, func(t *testing.T) {
			script := writeHermesProbeScript(t, body)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			ok := runHermesExecutionProbe(script, []string{"--defenseclaw-execution-probe"})
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			if ok {
				t.Fatal("probe with oversized output passed")
			}
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 16<<20 {
				t.Fatalf("probe allocated %d bytes for oversized output; want it capped", grew)
			}
			if elapsed > 10*time.Second {
				t.Fatalf("probe took %s; an output overflow must end it before the timeout", elapsed)
			}
		})
	}
}

// Neither a hook that exits while a descendant keeps stdout open nor a hung
// tree may hold Verify past the timeout plus the pipe wait.
func TestHermesExecutionProbeBoundsInheritedStdout(t *testing.T) {
	for name, tc := range map[string]struct {
		body    string
		timeout time.Duration
	}{
		"exits, descendant holds stdout":     {"printf 'defenseclaw-execution-probe-ok\\n'\nsleep 20 &\nexit 0\n", 20 * time.Second},
		"hangs, descendant holds stdout":     {"sleep 20 &\nsleep 20\n", 300 * time.Millisecond},
		"hangs after proof, ignores SIGTERM": {"trap '' TERM\nprintf 'defenseclaw-execution-probe-ok\\n'\nsleep 20 &\nsleep 20\n", 300 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			setHermesExecutionProbeBounds(t, tc.timeout, 500*time.Millisecond)
			script := writeHermesProbeScript(t, tc.body)
			done := make(chan bool, 1)
			start := time.Now()
			go func() { done <- runHermesExecutionProbe(script, []string{"--defenseclaw-execution-probe"}) }()
			select {
			case ok := <-done:
				if elapsed := time.Since(start); elapsed > 5*time.Second {
					t.Fatalf("probe took %s; want it bounded by the timeout and pipe wait", elapsed)
				}
				if tc.timeout < time.Second && ok {
					t.Fatal("timed-out probe passed")
				}
			case <-time.After(15 * time.Second):
				t.Fatal("probe still waiting on an inherited stdout after 15s")
			}
		})
	}
}
