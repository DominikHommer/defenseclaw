// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"testing"
	"time"
)

// GAP-0155: the hook command arms the answer watchdog of a tool call before
// it resolves its runtime, from the payload it reads first, and hands Run
// the same bytes.
func TestHookArmsTheAnswerWatchdogBeforeTheRuntimeResolution(t *testing.T) {
	savedSecureClient := secureClientHost
	secureClientHost = func() bool { return false }
	t.Cleanup(func() { secureClientHost = savedSecureClient })
	for _, test := range []struct {
		payload string
		armed   bool
	}{
		{`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, true},
		{`{"hook_event_name":"SessionStart"}`, false},
	} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.WriteString(test.payload); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		savedStdin := os.Stdin
		os.Stdin = reader
		stdin, watchdog := armHookAnswerWatchdog("claudecode", "", "", "", true, time.Now(), func(int) {})
		os.Stdin = savedStdin
		if (watchdog != nil) != test.armed {
			t.Fatalf("%s: watchdog armed=%v, want %v", test.payload, watchdog != nil, test.armed)
		}
		got, err := io.ReadAll(stdin)
		_ = reader.Close()
		if err != nil || string(got) != test.payload {
			t.Fatalf("Run would read %q (%v), want the agent's payload %q", got, err, test.payload)
		}
		if code := watchdog.Finish(7); code != 7 {
			t.Fatalf("Finish before the deadline returned %d, want the call's own 7", code)
		}
	}
}
