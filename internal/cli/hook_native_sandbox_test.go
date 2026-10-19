// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestNativeSandboxRuntimePresenceCannotFallThroughHostState(t *testing.T) {
	previous := nativeSandboxProfileLoad
	t.Cleanup(func() { nativeSandboxProfileLoad = previous })
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "must-not-be-read")
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "attacker.invalid:1234")
	for _, invalid := range []bool{false, true} {
		nativeSandboxProfileLoad = func() (*hookexec.NativeSandboxProfile, bool, error) {
			if invalid {
				return nil, true, errors.New("synthetic missing profile")
			}
			return &hookexec.NativeSandboxProfile{Version: 1, SessionID: strings.Repeat("a", 32), Connector: "claudecode", HookContract: "claude-contract-test"}, true, nil
		}
		opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "attacker.invalid:12", "open", true)
		if opts.NativeSandbox == nil || opts.Token != "" || opts.AuthenticatedManagedToken != nil || opts.ManagedEnterprise ||
			opts.GatewayRecovery != nil || opts.Home != hookexec.NativeSandboxHookDirectory || opts.FailMode != "closed" {
			t.Fatal("native profile selected host state or fallback")
		}
		if (opts.NativeSandbox.Validate() != nil) != invalid {
			t.Fatal("missing profile became a usable native descriptor")
		}
	}
}

func TestNativeSandboxNotifyRefusesBeforeOriginalCommand(t *testing.T) {
	previous := nativeSandboxProfileLoad
	t.Cleanup(func() { nativeSandboxProfileLoad = previous })
	nativeSandboxProfileLoad = func() (*hookexec.NativeSandboxProfile, bool, error) {
		return &hookexec.NativeSandboxProfile{Version: 1, SessionID: strings.Repeat("a", 32), Connector: "codex", HookContract: "codex-hooks-v4"}, true, nil
	}
	command := newNotifyCmd()
	command.SetArgs([]string{`{}`})
	if err := command.Execute(); err == nil {
		t.Fatal("native notify ran the unadmitted original-notify path")
	}
}
