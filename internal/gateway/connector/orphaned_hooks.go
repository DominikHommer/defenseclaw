// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"runtime"
	"strings"
)

// OrphanedHookConfigPaths returns the agent config files that still hold a
// DefenseClaw hook entry of conn for this data directory: an entry that runs
// one of conn's hook scripts under opts.DataDir/hooks (in any wrapping, such
// as the Claude Code missing-script guard), or the exact entry Setup writes
// for the native launcher on Windows. The caller has decided that conn is not
// configured, so each such entry is an orphan. A rollback restored a data
// directory from before the connector was set up, and Claude Code then ran a
// hook script that no longer existed and blocked every prompt (GAP-0009). A
// config file that cannot be read or parsed is an error, so nothing is
// removed on a guess.
func OrphanedHookConfigPaths(conn Connector, opts SetupOpts) ([]string, error) {
	exact := ownedHookCommandNeedles(opts, conn)
	scripts := ownedHookScriptPaths(conn, opts)
	if len(exact) == 0 && len(scripts) == 0 {
		return nil, nil
	}
	var found []string
	for _, path := range HookConfigPathsForConnector(conn, opts) {
		decoded, err := decodeHookConfigFile(path)
		if err != nil {
			return nil, err
		}
		if decoded == nil {
			continue
		}
		if structuredHookCommandReferences(decoded, exact) || hookCommandRunsScript(decoded, scripts) {
			found = append(found, path)
		}
	}
	return found, nil
}

// ownedHookScriptPaths lists the absolute paths of conn's Unix hook scripts in
// opts.DataDir. Windows registers the native launcher instead.
func ownedHookScriptPaths(conn Connector, opts SetupOpts) []string {
	owner, ok := conn.(HookScriptOwner)
	if !ok || runtime.GOOS == "windows" || strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	var paths []string
	for _, name := range owner.HookScriptNames(opts) {
		if name = strings.TrimSpace(name); name != "" {
			paths = append(paths, filepath.Join(hookDir, name))
		}
	}
	return paths
}

// hookCommandRunsScript reports whether a hook command anywhere in raw names
// one of scripts as a whole path (not a prefix of a longer file name).
func hookCommandRunsScript(raw interface{}, scripts []string) bool {
	if len(scripts) == 0 {
		return false
	}
	switch value := raw.(type) {
	case []interface{}:
		for _, item := range value {
			if hookCommandRunsScript(item, scripts) {
				return true
			}
		}
	case map[string]interface{}:
		for key, item := range value {
			if key == "command" || key == "bash" || key == "handler" {
				if command, ok := item.(string); ok && commandNamesScript(command, scripts) {
					return true
				}
			}
			if hookCommandRunsScript(item, scripts) {
				return true
			}
		}
	}
	return false
}

func commandNamesScript(command string, scripts []string) bool {
	for _, script := range scripts {
		for rest := command; ; {
			index := strings.Index(rest, script)
			if index < 0 {
				break
			}
			rest = rest[index+len(script):]
			if rest == "" || !strings.ContainsAny(rest[:1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/") {
				return true
			}
		}
	}
	return false
}
