// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 1.0.4 lead directive: the per-user GitHub Copilot CLI hook fails open
// upstream (Copilot has no fail-closed hook surface), so a gateway outage
// lets its tool call through whatever is installed or set in the
// environment. The docs say so plainly and promise no blocking; DefenseClaw
// records and reports the call. This pins the behavior and that text.
func TestPerUserCopilotHookFailsOpenUpstreamAsDocumented(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hooks")
	}
	for _, installed := range []string{"closed", "open"} {
		t.Run("installed="+installed, func(t *testing.T) {
			home := t.TempDir()
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", HookFailMode: installed}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewCopilotConnector()); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", filepath.Join(hookDir, "copilot-hook.sh"), "--event", "preToolUse")
			cmd.Stdin = strings.NewReader(`{"cwd":"/tmp","toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}`)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "DEFENSECLAW_HOME=" + home,
				"DEFENSECLAW_GATEWAY_AUTOSTART=0", "DEFENSECLAW_FAIL_MODE=closed", "DEFENSECLAW_STRICT_AVAILABILITY=1"}
			out, err := cmd.CombinedOutput()
			if err != nil || strings.Contains(string(out), `"permissionDecision":"deny"`) {
				t.Fatalf("per-user Copilot hook blocked an outage under env closed: err=%v\n%s", err, out)
			}
		})
	}
	for _, doc := range []struct {
		path string
		want []string
	}{
		{filepath.Join("..", "..", "..", "docs-site", "content", "docs", "reference", "fail-modes.mdx"), []string{
			"The per-user GitHub Copilot CLI hook cannot block a call while the gateway is down, on Linux, macOS and Windows.",
			"No setting changes this for a per-user install.",
			"`DEFENSECLAW_FAIL_MODE` is not read",
		}},
		{filepath.Join("..", "..", "envvars", "registry.json"), []string{
			"Not read by 1.0.4 hooks",
		}},
	} {
		data, err := os.ReadFile(doc.path)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		for _, want := range doc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not name the per-user Copilot exception: missing %q", doc.path, want)
			}
		}
	}
}
