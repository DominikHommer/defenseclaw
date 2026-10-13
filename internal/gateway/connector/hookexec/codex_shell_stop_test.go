// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
)

type codexShellTemplateData struct {
	APIAddr, FailMode, TokenFile, HookSocketTransportSH string
	Managed, SecureClient, Sandbox, ScopedToken         bool
}

func runCodexShellFailure(t *testing.T, managed bool, event, cause string) (int, string, string, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stubDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(stubDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\nexit 28\n"
	switch cause {
	case "invalid response":
		stub = "#!/bin/sh\nprintf '%s\\n' '{' '200'\n"
	case "unusable response":
		stub = "#!/bin/sh\nprintf '%s\\n' '{\"action\":\"unknown\"}' '200'\n"
	case "HTTP response":
		stub = "#!/bin/sh\nprintf '%s\\n' '{\"error\":\"unavailable\"}' '401'\n"
	case "gateway verdict":
		stub = "#!/bin/sh\nprintf '%s\\n' '{\"action\":\"block\",\"reason\":\"Policy block\",\"codex_output\":{\"decision\":\"block\",\"reason\":\"Policy block\"}}' '200'\n"
	}
	if err := os.WriteFile(filepath.Join(stubDir, "curl"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	data := codexShellTemplateData{APIAddr: "127.0.0.1:1", FailMode: "closed", TokenFile: ".hook-codex.token", Managed: managed, ScopedToken: true}
	if cause == "runtime unavailable" {
		data.HookSocketTransportSH = "fail_unreachable 'hook socket unavailable'\n"
	}
	raw, err := os.ReadFile("../hooks/codex-hook.sh")
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := template.Must(template.New("codex").Parse(string(raw))).Execute(&rendered, data); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hookDir, "codex-hook.sh")
	if err := os.WriteFile(hookPath, rendered.Bytes(), 0o700); err != nil {
		t.Fatal(err)
	}
	hardening, err := os.ReadFile("../hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	hardening = []byte(strings.Replace(string(hardening), `DEFENSECLAW_BAKED_HOOK_PATH=""`,
		`DEFENSECLAW_BAKED_HOOK_PATH="`+stubDir+`:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"`, 1))
	if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), hardening, 0o700); err != nil {
		t.Fatal(err)
	}
	if cause != "missing credential" {
		if err := os.WriteFile(filepath.Join(hookDir, data.TokenFile), []byte("fixture-token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", hookPath, "--event", event, "--hook-contract", "codex-hooks-v4")
	cmd.Env = append(os.Environ(), "HOME="+root, "DEFENSECLAW_HOME="+home,
		"DEFENSECLAW_FAIL_MODE=closed", "DEFENSECLAW_STRICT_AVAILABILITY=1", "DEFENSECLAW_GATEWAY_TOKEN=")
	if cause == "oversized body" {
		cmd.Env = append(cmd.Env, "DEFENSECLAW_HOOK_MAX_BODY=1")
	}
	cmd.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":%q}`, event))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	log, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	return code, stdout.String(), stderr.String(), string(log)
}

func TestCodexShellStopWithoutVerdictUsesNeutralResult(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, cause := range []string{"transport", "HTTP response", "invalid response", "unusable response", "oversized body", "missing credential", "runtime unavailable"} {
			if cause == "runtime unavailable" && !managed {
				continue
			}
			for _, event := range []string{"Stop", "PreToolUse", "PermissionRequest", "UserPromptSubmit"} {
				t.Run(fmt.Sprintf("managed=%v/%s/%s", managed, cause, event), func(t *testing.T) {
					code, stdout, stderr, log := runCodexShellFailure(t, managed, event, cause)
					if event == "Stop" {
						if code != 0 || stdout != "" || !strings.Contains(stderr, "not blocking the Stop event") {
							t.Fatalf("failed Stop = code %d, stdout %q, stderr %q", code, stdout, stderr)
						}
					} else if code == 0 && !strings.Contains(stdout, `"block"`) && !strings.Contains(stdout, `"deny"`) {
						t.Fatalf("failed %s did not block: code %d, stdout %q, stderr %q", event, code, stdout, stderr)
					}
					if !strings.Contains(log, `"fail_mode":"closed"`) {
						t.Fatalf("failure log = %q", log)
					}
				})
			}
		}
	}
	for _, managed := range []bool{false, true} {
		code, stdout, stderr, _ := runCodexShellFailure(t, managed, "Stop", "gateway verdict")
		if code != 0 || !strings.Contains(stdout, `"decision":"block"`) {
			t.Fatalf("managed=%v: code %d, stdout %q, stderr %q", managed, code, stdout, stderr)
		}
	}
}
