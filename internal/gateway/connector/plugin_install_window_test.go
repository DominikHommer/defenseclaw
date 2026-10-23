// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The installer holds this lock while it stops and replaces the account's
// gateway. A plugin using fail mode open must still stop actionable calls
// until that transaction has completed, for both a refused connection and a
// gateway error response. Once the lock is gone, its configured mode applies.
func pluginInstallWindowCases(t *testing.T, asset, extension, harness string) {
	t.Helper()
	nodeForTest(t)
	for _, failure := range []string{"transport", "http", "invalid-verdict"} {
		t.Run(failure, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			token := filepath.Join(dataDir, "hooks", ".hook-"+strings.TrimSuffix(asset, "-plugin"+extension)+".token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			data := templateData{APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token), FailMode: "open"}
			plugin := writeRenderedPlugin(t, asset, "defenseclaw."+strings.TrimPrefix(extension, "."), data)
			lock := filepath.Join(dataDir, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			blocked := runNodeHarness(t, harness, plugin, failure)
			if len(blocked) != 1 || !strings.HasPrefix(blocked[0], "block:") ||
				!strings.Contains(blocked[0], "being installed or upgraded") {
				t.Fatalf("%s with install lock = %q; want a block naming the install", failure, blocked)
			}
			if _, err := os.Stat(filepath.Join(dataDir, "logs", "hook-failures.jsonl")); !os.IsNotExist(err) {
				t.Fatalf("%s logged a blocked install call as fail-open: %v", failure, err)
			}
			if err := os.Remove(lock); err != nil {
				t.Fatal(err)
			}
			allowed := runNodeHarness(t, harness, plugin, failure)
			if len(allowed) != 1 || allowed[0] != "allow" {
				t.Fatalf("%s without install lock = %q; want configured fail-open", failure, allowed)
			}
		})
	}
}

const pluginInstallFailureFetch = `
globalThis.fetch = async () => {
  if (process.argv[2] === "transport") throw Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
  if (process.argv[2] === "invalid-verdict") return { ok: true, json: async () => ({ action: "unknown" }) };
  return { ok: false, status: 503 };
};
`

const openCodeInstallWindowHarness = `
import { pathToFileURL } from "node:url";
` + pluginInstallFailureFetch + `
const href = pathToFileURL(process.argv[1]).href;
const plugin = await (await import(href)).DefenseClaw({ directory: "", client: { tui: { showToast: async () => true } } });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
try {
  await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" }, { args: { command: "echo marker" } });
  console.log("allow");
} catch (error) {
  console.log("block:" + String(error && error.message || error));
}
`

func TestOpenCodePluginInstallWindowBlocksFailOpen(t *testing.T) {
	pluginInstallWindowCases(t, "opencode-plugin.js", ".js", openCodeInstallWindowHarness)
}

const ampInstallWindowHarness = `
import { pathToFileURL } from "node:url";
` + pluginInstallFailureFetch + `
globalThis.Bun = { file: () => ({ slice: () => ({ text: async () => "a".repeat(64) + "\n" }) }) };
const handlers = new Map();
const amp = {
  system: { workspaceRoot: "", executor: { kind: "local" }, user: {} },
  helpers: { filePathFromURI: value => value, isPluginUINotAvailableError: () => false },
  activeThread: { current: { id: "S" } },
  ui: { notify: async () => {} },
  on: (event, handler) => { handlers.set(event, handler); return { unsubscribe() {} }; },
};
(await import(pathToFileURL(process.argv[1]).href)).default(amp);
const ctx = { thread: { agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) }, ui: { confirm: async () => true } };
const event = { thread: { id: "S" }, toolUseID: "C", tool: "Bash", input: { command: "echo marker" } };
const call = await handlers.get("tool.call")(event, ctx);
const result = await handlers.get("tool.result")({ ...event, output: "result", status: "success" }, ctx);
console.log(JSON.stringify({ action: call.action, message: call.message || "", status: result?.status || "unchanged", error: result?.error || "" }));
`

func TestAmpPluginInstallWindowBlocksFailOpen(t *testing.T) {
	// Amp's two actionable boundaries must both block during the same window.
	for _, failure := range []string{"transport", "http", "invalid-verdict"} {
		t.Run(failure, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			token := filepath.Join(dataDir, "hooks", ".hook-amp.token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			plugin := writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", templateData{
				APIAddr: "127.0.0.1:1", TokenFileJS: javaScriptStringContent(token), FailMode: "open",
			})
			lock := filepath.Join(dataDir, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			check := func(wantBlocked bool) {
				t.Helper()
				lines := runNodeHarness(t, ampInstallWindowHarness, plugin, failure)
				if len(lines) != 1 {
					t.Fatalf("Amp verdict lines = %q", lines)
				}
				var verdict struct{ Action, Message, Status, Error string }
				if err := json.Unmarshal([]byte(lines[0]), &verdict); err != nil {
					t.Fatal(err)
				}
				if wantBlocked {
					if verdict.Action != "reject-and-continue" || verdict.Status != "error" ||
						!strings.Contains(verdict.Message, "being installed or upgraded") ||
						!strings.Contains(verdict.Error, "being installed or upgraded") {
						t.Fatalf("Amp with install lock = %+v; want both boundaries blocked", verdict)
					}
				} else if verdict.Action != "allow" || verdict.Status != "unchanged" {
					t.Fatalf("Amp without install lock = %+v; want configured fail-open", verdict)
				}
			}
			check(true)
			if err := os.Remove(lock); err != nil {
				t.Fatal(err)
			}
			check(false)
		})
	}
}
