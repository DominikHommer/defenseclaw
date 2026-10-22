// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"regexp"
	"strings"
	"testing"
)

// GAP-0464/GAP-0465: the capability matrix is the single connector outage
// reference. Keep its environment columns tied to the rendered hooks; the
// plugin outage tests exercise the installed modes against a stopped gateway.

// hookOnlyPlugin returns the in-agent plugin, if the connector owns one.
func hookOnlyPlugin(conn Connector) *hookOnlyConnector {
	switch c := conn.(type) {
	case *AMPConnector:
		return c.hookOnlyConnector
	case *hookOnlyConnector:
		if c.pluginArtifact {
			return c
		}
	}
	return nil
}

func pluginEnvRead(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?:process\.env\.|process\.env\[["']|environ(?:\.get)?\(\s*["']|environ\[["']|getenv\(\s*["'])` + name)
}

// The DEFENSECLAW_FAIL_MODE column: only the Secure Client delivery render
// of the hooks HookOutage names reads the variable; no other render does.
func TestHookOutageEnvFailModeMatchesTheRenderedHooks(t *testing.T) {
	for _, conn := range newBuiltinConnectors() {
		name := conn.Name()
		if IsProxyConnector(name) {
			continue
		}
		want := ConnectorHookOutage(conn).SecureClientEnvFailMode
		var bodies [][]byte
		if plugin := hookOnlyPlugin(conn); plugin != nil {
			for _, managed := range []bool{false, true} {
				opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", HookFailMode: "closed",
					ManagedEnterprise: managed, SecureClientHookDelivery: managed}
				body, err := plugin.renderPluginArtifact(opts)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
			}
		} else {
			names := conn.(HookScriptOwner).HookScriptNames(SetupOpts{})
			for _, delivery := range []bool{false, true} {
				for _, managed := range []bool{false, true} {
					scripts, err := renderHookScripts("127.0.0.1:18970", "closed", ".token", names, managed, name, true, "", "", managed, delivery)
					if err != nil {
						t.Fatal(err)
					}
					for _, script := range scripts {
						reads := strings.Contains(string(script.body), perUserEnvFailModeRead)
						expected := want && managed && delivery
						if strings.HasPrefix(script.name, "inspect-") {
							expected = false // the shared scripts serve every connector
						}
						if reads != expected {
							t.Errorf("%s %s (Secure Client %v, delivery %v): reads DEFENSECLAW_FAIL_MODE = %v, HookOutage.SecureClientEnvFailMode = %v",
								name, script.name, managed, delivery, reads, want)
						}
					}
				}
			}
			continue
		}
		if want {
			t.Errorf("%s: HookOutage says its Secure Client hook reads DEFENSECLAW_FAIL_MODE; only shell hooks do", name)
		}
		for _, body := range bodies {
			if pluginEnvRead("DEFENSECLAW_FAIL_MODE").Match(body) {
				t.Errorf("%s: rendered plugin or bridge reads DEFENSECLAW_FAIL_MODE", name)
			}
		}
	}
}

// Keep the strict-availability column tied to each rendered plugin input.
func TestHookOutageStrictAvailabilityMatchesThePlugins(t *testing.T) {
	for _, conn := range newBuiltinConnectors() {
		var body []byte
		var err error
		opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", HookFailMode: "open"}
		if plugin := hookOnlyPlugin(conn); plugin != nil {
			body, err = plugin.renderPluginArtifact(opts)
		} else {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		strict := ConnectorHookOutage(conn).StrictAvailability
		reads := pluginEnvRead("DEFENSECLAW_STRICT_AVAILABILITY").Match(body)
		if reads != (strict == StrictAvailabilityRead) {
			t.Errorf("%s: rendered per-user hook names DEFENSECLAW_STRICT_AVAILABILITY = %v, HookOutage.StrictAvailability = %q", conn.Name(), reads, strict)
		}
	}
}
