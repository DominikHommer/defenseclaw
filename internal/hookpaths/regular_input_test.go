//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSpecialInputReadsBounded(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(cwd, "input.pipe")
	if err := syscall.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(pipe, filepath.Join(cwd, "linked.pipe")); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(cwd, "large.txt")
	if err := os.WriteFile(large, make([]byte, 4097), 0600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, path string }{
		{"fifo", pipe}, {"linked_fifo", filepath.Join(cwd, "linked.pipe")},
		{"zero_device", "/dev/zero"}, {"null_device", "/dev/null"},
		{"large_regular", large},
	} {
		t.Run(row.name, func(t *testing.T) {
			command := fmt.Sprintf(`read f < %q; echo x >> "$f"`, row.path)
			body, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd, "tool_input": map[string]string{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan string, 1)
			go func() { done <- Resolve(body) }()
			select {
			case header := <-done:
				if _, ok := Decode(header); !ok {
					t.Fatal("incomplete analysis header")
				}
			case <-time.After(600 * time.Millisecond):
				t.Fatal("input analysis exceeded time limit")
			}
		})
	}
}
