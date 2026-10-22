// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// withHookSessionTestKeys accepts key files the test account made, where
// the gateway and the hook accept only root's.
func withHookSessionTestKeys(t *testing.T) {
	t.Helper()
	restore := enterprisepolicy.OverridePublishedSessionKeyOwnerForTest(func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return info.Mode().IsRegular(), nil
	})
	t.Cleanup(restore)
}

// hookSessionTestKeyID names the record folder's one key, or "".
func hookSessionTestKeyID(root string) string {
	key, err := enterprisepolicy.ReadPublishedSessionKey(root)
	if err != nil {
		return ""
	}
	return key.ID()
}

// Kill switch (GAP-0352, 1.0.4 guard loop round 1): every lifecycle run
// that changes anything removes the key of the protected session records
// first, before it sets an owner or takes its lock, and the package
// upgrade's ensure too; only a run that finished without an error makes a
// new key, as its last step, while it still holds the lock. Status and
// verify touch neither. A run that fails leaves no key, so every outage
// allow written before it, and since, proves nothing; uninstall leaves none
// either.
func TestTheLifecycleKillsTheHookSessionKeyFirstAndMakesANewOneLast(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			withHookSessionTestKeys(t)
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			root := h.env.P(h.env.Layout.HookSessionDir)
			if hookSessionTestKeyID(root) == "" {
				t.Fatal("an install must make a key")
			}
			if dir, _ := enterprisepolicy.PublishedSessionKeyDir(root); dir != h.env.P(h.env.Layout.HookSocketDir) {
				t.Fatalf("the key must be in the hook socket folder, which only root and the gateway can change: %s", dir)
			}
			var events []string
			// locked reports whether a lifecycle run holds the lock.
			locked := func() bool {
				lock, err := h.env.acquireLock(context.Background())
				if err != nil {
					return true
				}
				lock.release()
				return false
			}
			previousRetire, previousCreate, previousLchown := hookSessionRetireKey, hookSessionCreateKey, h.env.Lchown
			t.Cleanup(func() {
				hookSessionRetireKey, hookSessionCreateKey, h.env.Lchown = previousRetire, previousCreate, previousLchown
			})
			hookSessionRetireKey = func(path string, trust enterprisepolicy.PublishedSessionTrust) error {
				if locked() {
					t.Error("the key must go before the run takes its lock")
				}
				events = append(events, "kill")
				return previousRetire(path, trust)
			}
			hookSessionCreateKey = func(path string, trust enterprisepolicy.PublishedSessionTrust) error {
				if !locked() {
					t.Error("the new key must be made while the run still holds the lock")
				}
				events = append(events, "create")
				return previousCreate(path, trust)
			}
			h.env.Lchown = func(path string, uid, gid int) error {
				events = append(events, "chown")
				return previousLchown(path, uid, gid)
			}
			for _, opts := range []Options{{Action: ActionEnsure, PayloadDir: h.payload("1.0.1")}, {Action: ActionRepair}, {Action: ActionEnsure}} {
				events = nil
				old := hookSessionTestKeyID(root)
				requireOK(t, h.run(opts))
				if len(events) < 2 || events[0] != "kill" || events[len(events)-1] != "create" {
					t.Fatalf("%s: the key must go first and a new one come last: %v", opts.Action, events)
				}
				if now := hookSessionTestKeyID(root); now == "" || now == old {
					t.Fatalf("%s: the run must end with a new key: %q (was %q)", opts.Action, now, old)
				}
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				events = nil
				old := hookSessionTestKeyID(root)
				h.run(Options{Action: action})
				if len(events) != 0 || hookSessionTestKeyID(root) != old {
					t.Fatalf("%s must touch no key: %v", action, events)
				}
			}
			// A run that fails makes no new key.
			h.healthy = false
			events = nil
			if result := h.run(Options{Action: ActionRepair}); len(result.Errors) == 0 {
				t.Fatal("a repair of an unhealthy gateway must fail")
			}
			if len(events) == 0 || events[0] != "kill" {
				t.Fatalf("a failing run removes the key first too: %v", events)
			}
			for _, event := range events {
				if event == "create" {
					t.Fatalf("a failed run must make no new key: %v", events)
				}
			}
			if hookSessionTestKeyID(root) != "" {
				t.Fatal("a failed run must leave no key")
			}
			h.healthy = true
			requireOK(t, h.run(Options{Action: ActionRepair}))
			if hookSessionTestKeyID(root) == "" {
				t.Fatal("the next repair must make a key")
			}
			// A key that cannot be removed is reported, and the run goes on.
			hookSessionRetireKey = func(string, enterprisepolicy.PublishedSessionTrust) error {
				return errors.New("read-only file system")
			}
			result := h.run(Options{Action: ActionRepair})
			found := false
			for _, warning := range result.Warnings {
				found = found || warning.Code == codeHookSessionKey
			}
			if len(result.Errors) != 0 || !found {
				t.Fatalf("a key that cannot be removed must be a warning: %+v", result)
			}
			hookSessionRetireKey = previousRetire
			// Uninstall removes the key and makes none.
			events = nil
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			for _, event := range events {
				if event == "create" {
					t.Fatalf("an uninstall must make no key: %v", events)
				}
			}
			if keys, _ := filepath.Glob(filepath.Join(h.env.P(h.env.Layout.HookSocketDir), filepath.Base(root)+enterprisepolicy.PublishedSessionKeyInfix+"*")); len(keys) != 0 {
				t.Fatalf("an uninstall must leave no key: %v", keys)
			}
		})
	}
}
