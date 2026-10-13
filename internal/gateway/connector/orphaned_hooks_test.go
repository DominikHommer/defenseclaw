// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// rel-1-0-1:GAP-0009: an orphaned entry is found by the hook script path it
// runs, in any wrapping, and never by a longer name that starts with it.
func TestCommandNamesScriptMatchesWholePathsOnly(t *testing.T) {
	scripts := []string{"/home/u/.defenseclaw/hooks/claude-code-hook.sh"}
	for command, want := range map[string]bool{
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh":                                                     true,
		"'/home/u/.defenseclaw/hooks/claude-code-hook.sh' --event Stop":                                      true,
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh || { rc=$?; exit 2; }":                               true,
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh.bak":                                                 false,
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh2":                                                    false,
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh.old; /home/u/.defenseclaw/hooks/claude-code-hook.sh": true,
		"/opt/operator/hooks/claude-code-hook.sh":                                                            false,
	} {
		if got := commandNamesScript(command, scripts); got != want {
			t.Errorf("commandNamesScript(%q) = %v, want %v", command, got, want)
		}
	}
}

func TestHookCommandRunsScriptLooksOnlyAtCommands(t *testing.T) {
	scripts := []string{"/d/hooks/codex-hook.sh"}
	doc := map[string]interface{}{
		"description": "/d/hooks/codex-hook.sh",
		"hooks": map[string]interface{}{
			"Stop": []interface{}{map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"command": "/usr/bin/true"}}}},
		},
	}
	if hookCommandRunsScript(doc, scripts) {
		t.Fatal("a non-command field counted as a hook entry")
	}
	doc["hooks"].(map[string]interface{})["Stop"] = []interface{}{
		map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"command": "/d/hooks/codex-hook.sh"}}},
	}
	if !hookCommandRunsScript(doc, scripts) {
		t.Fatal("the hook entry that runs the script was not found")
	}
}
