// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 1.0.4 review (loop round 3 of G-hooks-upg): the docs said the
// administrator's hook_fail_mode: open lets a managed standalone Copilot
// preToolUse or permissionRequest call run during a gateway outage. That is
// the Windows native hook (hookexec managedCopilotOpen). On Linux and macOS
// the managed hook is copilot-hook.sh, which renders FAIL_MODE closed for a
// managed standalone install and answers every failure with Copilot's
// native deny (copilot_managed_failure), whatever the administrator chose.
// That is the closed side, so the docs follow the hook, not the other way
// round. This runs the real managed render with the gateway service up
// (the call is answered, no deny) and stopped (hook socket gone) in both
// installed modes and for both blockable events, and pins that every page
// that describes the outage names the Linux and macOS exception.
func TestManagedUnixCopilotOutageBlocksInEveryFailModeAsDocumented(t *testing.T) {
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		if _, err := os.Stat("/usr/local/bin/jq"); err != nil {
			t.Skip("jq is required to run the Copilot shell hook")
		}
	}
	denies := map[string]string{
		"preToolUse":        `"permissionDecision":"deny"`,
		"permissionRequest": `"behavior":"deny"`,
	}
	payload := `{"cwd":"/tmp","toolName":"bash","toolArgs":"{\"command\":\"echo marker\"}"}`
	for _, mode := range []string{"open", "closed"} {
		for event, deny := range denies {
			t.Run(mode+"/"+event, func(t *testing.T) {
				f := newHookSocketFixture(t, "dcuc", map[string]interface{}{"action": "allow", "hook_output": map[string]string{}})
				args := []string{"--event", event}
				code, stdout, stderr := runStandaloneShellHookInMode(t, f, NewCopilotConnector(), "copilot-hook.sh", args, payload, mode)
				if code != 0 || strings.Contains(stdout, "deny") {
					t.Fatalf("running gateway answered allow: exit %d stdout=%q stderr=%q, want no deny", code, stdout, stderr)
				}
				if err := os.Remove(f.socket); err != nil {
					t.Fatal(err)
				}
				code, stdout, stderr = runStandaloneShellHookInMode(t, f, NewCopilotConnector(), "copilot-hook.sh", args, payload, mode)
				if code != 0 || !strings.Contains(stdout, deny) {
					t.Fatalf("installed mode %q, gateway stopped: exit %d stdout=%q stderr=%q, want Copilot's native deny %s",
						mode, code, stdout, stderr, deny)
				}
			})
		}
	}
	docs := filepath.Join("..", "..", "..", "docs-site", "content", "docs")
	for _, doc := range []struct {
		path      string
		want      []string
		forbidden []string
	}{
		{filepath.Join(docs, "connectors", "copilot.mdx"), []string{
			"On Linux and macOS it denies `preToolUse` and `permissionRequest` while the gateway service is not running in every fail mode, the administrator's `hook_fail_mode: open` included.",
		}, []string{
			"running. With the administrator's `hook_fail_mode: open` it lets them run.",
		}},
		{filepath.Join(docs, "reference", "fail-modes.mdx"), []string{
			"The one exception is the managed GitHub Copilot CLI hook on Linux and macOS, which blocks during an outage in every fail mode",
			"and for GitHub Copilot CLI only on Windows: on Linux and macOS the managed Copilot hook blocks `preToolUse` and `permissionRequest` during an outage in `open` too.",
			"No (managed standalone: blocks `preToolUse` and `permissionRequest` while the gateway is down; on Linux and macOS in every fail mode,",
			"On Linux and macOS it blocks them in every fail mode, the administrator's `hook_fail_mode: open` included.",
		}, []string{
			"Only the administrator's `hook_fail_mode: open` lets such a call through. ",
			"An administrator-managed standalone Copilot hook can block `preToolUse` and `permissionRequest` while the gateway service is not running, but only in the effective mode",
		}},
		{filepath.Join(docs, "connectors", "capability-matrix.mdx"), []string{
			"The managed Copilot hook on Linux and macOS never lets `preToolUse` or `permissionRequest` run during an outage, `open` included.",
		}, nil},
		{filepath.Join(docs, "enterprise", "troubleshooting.mdx"), []string{
			"except the GitHub Copilot CLI hook on Linux and macOS, which denies `preToolUse` and `permissionRequest` in every fail mode",
			"A GitHub Copilot CLI `preToolUse` or `permissionRequest` call on Linux and macOS is blocked in `open` too.",
		}, nil},
	} {
		data, err := os.ReadFile(doc.path)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		for _, want := range doc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not name the Linux and macOS managed Copilot exception: missing %q", doc.path, want)
			}
		}
		for _, forbidden := range doc.forbidden {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s still says the managed Copilot hook follows open on every OS: %q", doc.path, forbidden)
			}
		}
	}
}
