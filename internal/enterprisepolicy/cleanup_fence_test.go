// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The guardian's cleanup fence is taken in BeforeRemove: it must run before
// every kind of removal (a JSON rewrite, a Hermes rewrite, a plugin moved
// aside), never when there is nothing to remove, and a refusal must leave
// the hook in place and reported.
func TestCleanupAsksBeforeEveryRemovalAndOnlyThen(t *testing.T) {
	type fixture struct {
		req     GuardRequest
		path    string
		removed func() bool
	}
	cursor := func(t *testing.T) fixture {
		req := guardRequest(t, "cursor", config.ForeignHooksRemove)
		path := filepath.Join(req.Home, ".cursor", "hooks.json")
		writeFile(t, path, `{"version": 1, "hooks": {"preToolUse": [`+ownedCursorEntry+`, {"command": "./rewrite.sh"}]}}`)
		return fixture{req, path, func() bool { return !strings.Contains(readFile(t, path), "rewrite.sh") }}
	}
	hermes := func(t *testing.T) fixture {
		req, script := hermesGuardRequest(t, config.ForeignHooksRemove)
		path := filepath.Join(req.Home, ".hermes", "config.yaml")
		writeFile(t, path, hermesConfig(script, hermesRewriteEntry))
		return fixture{req, path, func() bool { return !strings.Contains(readFile(t, path), "rewrite-tool-input.sh") }}
	}
	plugin := func(t *testing.T) fixture {
		req := guardRequest(t, "opencode", config.ForeignHooksRemove)
		req.AccountHome = req.Home
		path := filepath.Join(req.Home, ".config", "opencode", "plugins", "mutate.mjs")
		writeFile(t, path, "export default {}")
		return fixture{req, path, func() bool { _, err := os.Lstat(path); return os.IsNotExist(err) }}
	}
	for name, build := range map[string]func(*testing.T) fixture{"json": cursor, "hermes": hermes, "plugin dir": plugin} {
		t.Run(name, func(t *testing.T) {
			f := build(t)
			calls := 0
			f.req.BeforeRemove = func() error {
				calls++
				if f.removed() {
					t.Error("BeforeRemove ran after the removal")
				}
				return nil
			}
			result, err := CleanUserForeignHooks(f.req, time.Now())
			if err != nil || len(result.Removed) == 0 || !f.removed() || calls == 0 {
				t.Fatalf("cleanup with the fence granted: calls=%d result=%+v err=%v", calls, result, err)
			}

			// Nothing left to remove: the fence is never asked for.
			calls = 0
			if _, err := CleanUserForeignHooks(f.req, time.Now()); err != nil || calls != 0 {
				t.Fatalf("a clean config asked for the fence %d times: %v", calls, err)
			}

			// Refused: the hook stays, reported, and the error surfaces.
			g := build(t)
			refused := errors.New("fence unavailable")
			g.req.BeforeRemove = func() error { return refused }
			result, err = CleanUserForeignHooks(g.req, time.Now())
			if !errors.Is(err, refused) || len(result.Removed) != 0 || len(result.Reported) == 0 || g.removed() {
				t.Fatalf("a refused fence must leave the hook in place: result=%+v err=%v", result, err)
			}
			if result.BackupDir != "" {
				t.Fatalf("a refused removal left a backup: %s", result.BackupDir)
			}
		})
	}
}
