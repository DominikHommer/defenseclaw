// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedClaudeResolvedWriteRunnerRestoresAddressLimit(t *testing.T) {
	testManagedResolvedWriteRunnerRestoresAddressLimit(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil)
}

func TestManagedCodexResolvedWriteRunnerRestoresAddressLimit(t *testing.T) {
	testManagedResolvedWriteRunnerRestoresAddressLimit(t, NewCodexConnector(), "codex-hook.sh", []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"})
}

func testManagedResolvedWriteRunnerRestoresAddressLimit(t *testing.T, c Connector, scriptName string, args []string) {
	t.Helper()
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to run shell hooks")
	}
	f := newHookSocketFixture(t, "dcrw", nil)
	home := filepath.Join(f.root, "home")
	dataDir := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	bin := filepath.Join(f.root, "bin", "defenseclaw-hook")
	if err := os.Mkdir(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	limits := filepath.Join(f.root, "resolver-limits")
	stub := "#!/bin/bash\n" +
		"[ \"$1 $2\" = 'hook resolve-writes' ] || exit 0\n" +
		"printf '%s\\n%s\\n' \"$(ulimit -S -v)\" \"$(ulimit -H -v)\" > " + shellSingleQuoteForTest(limits) + "\n" +
		"printf 'e30=\\n'\n"
	if err := os.WriteFile(bin, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: dataDir, APIAddr: f.held.Addr().String(), APIToken: "fixture-token", ManagedEnterprise: true,
		HookFailMode: "closed", ManagedHookSocket: f.socket, ManagedServiceUID: os.Getuid(), ManagedHookBinary: bin}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hookDir, scriptName)
	bakeHookPathForTest(t, hookPath, filepath.Dir(curlPath)+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{hookPath}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = strings.NewReader(`{"session_id":"limit-test","hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"echo ok"}}`)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("hook exit: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	got, err := os.ReadFile(limits)
	if err != nil {
		t.Fatalf("resolver was not invoked: %v; stderr=%q", err, stderr.String())
	}
	parts := strings.Fields(string(got))
	if len(parts) != 2 || parts[0] != parts[1] {
		t.Fatalf("resolver soft/hard address limits = %q, want equal", strings.TrimSpace(string(got)))
	}
	f.gateway.mu.Lock()
	resolved := append([]string(nil), f.gateway.resolved...)
	f.gateway.mu.Unlock()
	if len(resolved) != 1 || resolved[0] != "e30=" {
		t.Fatalf("resolved-write headers = %q, want the resolver's non-truncated map", resolved)
	}
	f.requireOnlyTheTrustedRequest(t, "/api/v1/"+map[string]string{"claudecode": "claude-code", "codex": "codex"}[c.Name()]+"/hook")
}
