// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package main

import (
	"context"
	"io"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/test/e2e/axis/native-hook-canary/fixture"
)

func TestFixedHookExchangeUsesExistingNativeClientWithoutOverride(t *testing.T) {
	value, _ := fixture.Lookup("claudecode")
	profile := &hookexec.NativeSandboxProfile{Version: 1, SessionID: "fixed-session", Connector: "claudecode", HookContract: "claudecode-hooks-v1"}
	for _, phase := range []byte{'A', 'B', 'L'} {
		calls := 0
		row, err := exchange(context.Background(), profile, value, phase, func(_ context.Context, opts hookexec.Options) int {
			calls++
			if opts.NativeSandbox != profile || opts.HTTPClient != nil || opts.Token != "" || opts.ManagedUnixSocket != "" || opts.Event != value.Event {
				t.Fatal("native invocation changed authority or dialect")
			}
			raw, _ := io.ReadAll(opts.Stdin)
			want, _ := value.Payload(phase)
			if string(raw) != string(want) {
				t.Fatal("schema changed before existing client")
			}
			_, _ = io.WriteString(opts.Stdout, "fixed native output")
			return 2
		})
		if err != nil || calls != 1 || row.Code != 2 || row.Stdout != "fixed native output" {
			t.Fatal("client result not retained")
		}
	}
}
