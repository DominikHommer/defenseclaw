// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// 1.0.4 review (loop round 1 of G-hooks-upg): the docs said the
// administrator's hook_fail_mode: open lets a managed standalone call run
// during a gateway outage for every connector but the Linux and macOS
// Copilot hook. The Amp and OpenCode plugins are rendered with
// DC_FAIL_MODE "closed" for a managed standalone install that has the hook
// socket (Linux and macOS), so they block an outage in every fail mode,
// whatever the administrator chose; the Windows standalone render keeps the
// resolved mode. That is the closed side, so the docs follow the plugins,
// not the other way round. This renders the plugins the way Setup does
// (renderPluginArtifact) for both installed modes and both layouts, runs
// them against a stopped gateway, and pins that every page that describes
// the managed outage says so.
func TestManagedAmpAndOpenCodeOutageFollowTheDocumentedFailMode(t *testing.T) {
	failModeRE := regexp.MustCompile(`const DC_FAIL_MODE(?:: string)? = "([a-z]*)"`)
	plugins := map[string]*hookOnlyConnector{"amp": NewAMPConnector().hookOnlyConnector, "opencode": NewOpenCodeConnector()}
	for name, c := range plugins {
		for _, layout := range []string{"unix", "windows"} {
			for _, mode := range []string{"open", "closed"} {
				opts := managedPluginOutageOpts(t, name, layout, mode, filepath.Join(testenv.PrivateTempDir(t), "defenseclaw-hook"), "127.0.0.1:18970")
				body, err := c.renderPluginArtifact(opts)
				if err != nil {
					t.Fatalf("%s %s %s: render: %v", name, layout, mode, err)
				}
				want := mode
				if layout == "unix" {
					want = "closed" // every fail mode, the administrator's open included
				}
				if got := failModeRE.FindSubmatch(body); got == nil || string(got[1]) != want {
					t.Errorf("%s %s installed mode %q: rendered %q, want DC_FAIL_MODE %q", name, layout, mode, got, want)
				}
			}
		}
	}

	if runtime.GOOS == "windows" {
		t.Log("the plugin runs below use a shell stand-in for the hook binary; the render checks above cover Windows")
	} else {
		nodeForTest(t)
		for name, c := range plugins {
			for _, layout := range []string{"unix", "windows"} {
				for _, mode := range []string{"open", "closed"} {
					root := testenv.PrivateTempDir(t)
					guard := filepath.Join(root, "defenseclaw-hook")
					// The foreign-hook check answers allow; any other call of the
					// hook binary (session facts) gets no answer.
					if err := os.WriteFile(guard, []byte("#!/bin/sh\ncat >/dev/null\ncase \" $* \" in\n  *\" --foreign-hook-check \"*) printf '{\"deny\":false}\\n' ;;\n  *) exit 1 ;;\nesac\n"), 0o700); err != nil {
						t.Fatal(err)
					}
					opts := managedPluginOutageOpts(t, name, layout, mode, guard, stoppedGatewayAddr(t))
					body, err := c.renderPluginArtifact(opts)
					if err != nil {
						t.Fatal(err)
					}
					want := "allow"
					if layout == "unix" || mode == "closed" {
						want = "block"
					}
					for _, got := range runManagedPluginOutage(t, name, root, body) {
						if !strings.HasPrefix(got, want) {
							t.Errorf("%s %s installed mode %q, gateway stopped: %q, want %s", name, layout, mode, got, want)
						}
					}
				}
			}
		}
	}

	docs := filepath.Join("..", "..", "..", "docs-site", "content", "docs")
	for _, doc := range []struct {
		path      string
		want      []string
		forbidden []string
	}{
		{filepath.Join(docs, "reference", "fail-modes.mdx"), []string{
			"On Linux and macOS three managed hooks are the exception and block during an outage in every fail mode: the Amp and OpenCode plugins",
			"That is the administrator's resolved value, so on Linux and macOS it can say `open` for the Amp and OpenCode plugins and the GitHub Copilot CLI hook while they block an outage.",
			"On Linux and macOS the Amp and OpenCode plugins and the GitHub Copilot CLI hook block an outage in `open` too.",
			"so an outage still lets the call run (on Linux and macOS not through the Amp and OpenCode plugins or the GitHub Copilot CLI hook, which block it in every fail mode).",
			"| OpenCode | `tool.execute.before` | None | Yes (managed standalone on Linux and macOS: blocks while the gateway is down in every fail mode, `open` included) |",
			"| Amp | `tool.call`, `tool.result` | `tool.call`, `tool.result` (foreground thread) | Yes (managed standalone on Linux and macOS: blocks while the gateway is down in every fail mode, `open` included) |",
			"the managed Amp plugin on Linux and macOS blocks an outage in every fail mode",
			"## Managed Amp and OpenCode plugins On a managed standalone Linux or macOS host the administrator-owned Amp and OpenCode plugins are installed fail-closed whatever `hook_fail_mode` says.",
			"On a managed Windows host they follow the effective mode: `closed` (the default) blocks an outage, and the administrator's `hook_fail_mode: open` lets the call run.",
		}, []string{
			"The one exception is the managed GitHub Copilot CLI hook",
			"as every other connector does in fail mode `open`",
			"| OpenCode | `tool.execute.before` | None | Yes |",
			"| Amp | `tool.call`, `tool.result` | `tool.call`, `tool.result` (foreground thread) | Yes |",
		}},
		{filepath.Join(docs, "connectors", "capability-matrix.mdx"), []string{
			"Neither do the managed Amp and OpenCode plugins on Linux and macOS, for any call they check.",
		}, nil},
		{filepath.Join(docs, "enterprise", "troubleshooting.mdx"), []string{
			"and the Amp and OpenCode plugins on Linux and macOS, which deny the call in every fail mode; see [Fail modes](/docs/reference/fail-modes))",
			"So is a call the Amp or OpenCode plugin checks on Linux and macOS.",
		}, []string{
			"It is never an allow unless the administrator set `hook_fail_mode: open`. ",
		}},
		{filepath.Join(docs, "connectors", "amp.mdx"), []string{
			"hook failure mode, except on a managed standalone Linux or macOS host, where the administrator-owned plugin blocks in every fail mode, the administrator's `hook_fail_mode: open` included",
		}, []string{
			"Gateway errors honor the configured open/closed hook failure mode. ",
		}},
		{filepath.Join(docs, "connectors", "opencode.mdx"), []string{
			"`FAIL_MODE=open` allows. On a managed standalone Linux or macOS host the administrator-owned plugin blocks in every fail mode, the administrator's `hook_fail_mode: open` included",
		}, nil},
	} {
		data, err := os.ReadFile(doc.path)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		for _, want := range doc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s: missing %q", doc.path, want)
			}
		}
		for _, forbidden := range doc.forbidden {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s: still says %q", doc.path, forbidden)
			}
		}
	}
}

// managedPluginOutageOpts are the standalone Setup options of one layout:
// "unix" carries the hook socket and the administrator-owned hook binary
// (enterprise_hooks_standalone_unix.go), "windows" only the foreign-hook
// guard and the TCP gateway (install_windows.go).
func managedPluginOutageOpts(t *testing.T, name, layout, mode, guard, apiAddr string) SetupOpts {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	opts := SetupOpts{
		DataDir:                filepath.Join(root, "defenseclaw"),
		APIAddr:                apiAddr,
		ManagedEnterprise:      true,
		HookFailMode:           mode,
		ForeignHookGuardBinary: guard,
	}
	if layout == "unix" {
		opts.ManagedHookSocket = filepath.Join(root, "hook.sock") // never created: the service is stopped
		opts.ManagedHookBinary = guard
		opts.ManagedServiceUID = os.Getuid()
	}
	token, err := HookAPITokenFilePath(opts.DataDir, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return opts
}

// stoppedGatewayAddr is a loopback address nothing listens on.
func stoppedGatewayAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// runManagedPluginOutage loads the rendered plugin and sends it one call per
// blockable event, printing "allow" or "block:<reason>" for each.
func runManagedPluginOutage(t *testing.T, name, root string, body []byte) []string {
	t.Helper()
	file := filepath.Join(root, "defenseclaw.mjs")
	harness := managedOpenCodeOutageHarness
	if name == "amp" {
		file, harness = filepath.Join(root, "defenseclaw.mts"), managedAmpOutageHarness
	}
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	lines := runNodeHarness(t, harness, file)
	if want := map[string]int{"amp": 2, "opencode": 1}[name]; len(lines) != want {
		t.Fatalf("%s: harness printed %q, want %d verdicts", name, lines, want)
	}
	return lines
}

const managedOpenCodeOutageHarness = `
import { pathToFileURL } from "node:url";
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const plugin = await loaded.DefenseClaw({ directory: "", client: {} });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
try {
  await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C1" }, { args: { command: "echo marker" } });
  console.log("allow");
} catch (error) {
  console.log("block:" + String(error && error.message || error));
}
`

const managedAmpOutageHarness = `
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
// Amp runs plugins on Bun; the plugin reads its credential with Bun.file.
globalThis.Bun = { file: (path) => ({ slice: () => ({ text: async () => readFileSync(path, "utf8") }) }) };
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
const ctx = { thread: { id: "T", agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) }, ui: { notify: async () => {} } };
const call = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: "U1", tool: "Bash", input: { command: "echo marker" } }, ctx);
console.log(call.action === "allow" ? "allow" : "block:" + call.message);
const result = await handlers["tool.result"]({ thread: { id: "T" }, toolUseID: "U1", tool: "Bash", input: { command: "echo marker" }, output: "marker", status: "done" }, ctx);
console.log(result ? "block:" + result.error : "allow");
`
