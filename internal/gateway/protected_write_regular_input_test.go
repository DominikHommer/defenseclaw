//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestProtectedWriteRegularInputDecision(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(key), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(cwd, "input.pipe")
	if err := syscall.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(pipe, filepath.Join(cwd, "linked.pipe")); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(cwd, "input.txt")
	if err := os.WriteFile(regular, []byte("disklink\n"), 0600); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(cwd, "large.txt")
	if err := os.WriteFile(large, make([]byte, 4097), 0600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, path string }{
		{"fifo", pipe}, {"linked_fifo", filepath.Join(cwd, "linked.pipe")},
		{"zero_device", "/dev/zero"}, {"null_device", "/dev/null"},
		{"large_regular", large}, {"known_regular", regular},
	} {
		for _, managed := range []bool{false, true} {
			t.Run(row.name+map[bool]string{false: "/per_user", true: "/managed"}[managed], func(t *testing.T) {
				input := actionfacts.Input{Tool: "Bash", Command: fmt.Sprintf(`read f < %q; echo x >> "$f"`, row.path), CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				request := trustedActionRequest{Input: input, ProtectedHomeHook: managed}
				if managed {
					request.ResolvedWriteTargets = map[string]string{hookpaths.CWDKey: cwd}
				}
				done := make(chan bool, 1)
				go func() { done <- trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) }()
				select {
				case blocked := <-done:
					if !blocked {
						t.Fatal("unknown or protected write was allowed")
					}
				case <-time.After(600 * time.Millisecond):
					t.Fatal("decision analysis exceeded time limit")
				}
			})
		}
	}
}
