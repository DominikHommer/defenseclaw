// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// hookSessionTestKey is the agent process the record tests publish for.
var hookSessionTestKey = enterprisepolicy.SessionKey{Connector: "copilot", Session: "s-1", Process: "linux:b:1:100"}

// publishHookSessionTestAllow writes account 1001's allow record under root,
// as the gateway does: stamped with the current generation. It returns the
// record's path.
func publishHookSessionTestAllow(t *testing.T, root string) string {
	t.Helper()
	path, ok := enterprisepolicy.PublishedSessionRecordPath(root, "1001", hookSessionTestKey.Connector, "p", hookSessionTestKey.Process)
	if !ok {
		t.Fatal("no record path")
	}
	generationPath, _ := enterprisepolicy.PublishedSessionGenerationPath(root)
	info, err := os.Lstat(generationPath)
	if err != nil {
		t.Fatalf("the record folder must have a generation: %v", err)
	}
	data, err := json.Marshal(enterprisepolicy.PublishedSessionRecord{Version: 2, Connector: hookSessionTestKey.Connector, Kind: "p",
		ID: hookSessionTestKey.Process, At: time.Now().UTC().Format(time.RFC3339), Generation: strconv.FormatInt(info.ModTime().UnixNano(), 10)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if !hookSessionTestProves(root) {
		t.Fatal("a fresh allow of the current generation must prove the process")
	}
	return path
}

// hookSessionTestProves reports whether account 1001's record under root
// proves its agent process unblocked during an outage (the hook's check,
// without the ownership rules a fake host cannot meet).
func hookSessionTestProves(root string) bool {
	_, err := enterprisepolicy.CheckPublishedForeignHookSession(root, "1001", hookSessionTestKey, enterprisepolicy.GuardDecision{},
		func(string) error { return nil })
	return err == nil
}

// Lead directive (GAP-0352 review loop round 1): no repair, upgrade or ensure
// re-trusts a record written before it, whatever another account did while
// the tree was loosened, with no tree check and no record found or deleted.
// The run bumps the generation first and again with the record folder
// closed, so every earlier allow proves nothing: one in a tree nobody
// touched, one whose folder the account moved aside and back while the
// record folder was writable, and one whose whole record folder, with its
// own generation file, the account moved away and brought back while the
// folder above it was writable, after the first bump and before that
// folder's mode went back.
func TestRepairNeverReTrustsAHookSessionRecord(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	root := h.env.P(h.env.Layout.HookSessionDir)
	parent := filepath.Dir(root)

	publishHookSessionTestAllow(t, root)
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if hookSessionTestProves(root) {
		t.Fatal("a repair must end the allow of a tree nobody touched")
	}

	record := publishHookSessionTestAllow(t, root)
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	aside := filepath.Join(parent, "aside")
	if err := os.Rename(filepath.Dir(record), aside); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, filepath.Dir(record)); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if hookSessionTestProves(root) {
		t.Fatal("the folder the account moved aside and back must prove nothing after the repair")
	}

	publishHookSessionTestAllow(t, root)
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	away := filepath.Join(t.TempDir(), "sessions")
	if err := os.Rename(root, away); err != nil {
		t.Fatal(err)
	}
	moved := false
	previousLchown := h.env.Lchown
	h.env.Lchown = func(path string, uid, gid int) error {
		if path == parent && !moved {
			// The run puts the folder above back: the account brings its
			// old record folder, with its own generation file, back first.
			moved = true
			if err := os.RemoveAll(root); err != nil {
				return err
			}
			if err := os.Rename(away, root); err != nil {
				return err
			}
			if !hookSessionTestProves(root) {
				return errors.New("the brought-back folder must still hold its own allow")
			}
		}
		return previousLchown(path, uid, gid)
	}
	t.Cleanup(func() { h.env.Lchown = previousLchown })
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if !moved {
		t.Fatal("the repair must put the folder above the record folder back")
	}
	if hookSessionTestProves(root) {
		t.Fatal("a record folder brought back with its own generation must prove nothing after the repair")
	}
	for path, mode := range map[string]os.FileMode{root: 0o711, parent: 0o755} {
		if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s: the mode must be put back: %v %v", path, info, err)
		}
	}
}

// Lead directive (GAP-0352 review loop round 1): a lifecycle run bumps the
// generation before it changes anything, the package upgrade's ensure
// included, and bumps it again with the record folder closed to every
// account (0700, the owner put back first: an account that owned the folder
// cannot open it again in between), before the folder's mode goes back.
func TestTheLifecycleBumpsTheHookSessionGenerationFirstAndWhileClosed(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	root := h.env.P(h.env.Layout.HookSessionDir)
	var events []string
	previousBump := hookSessionBump
	hookSessionBump = func(path string) error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		events = append(events, "bump "+strconv.FormatUint(uint64(info.Mode().Perm()), 8))
		return previousBump(path)
	}
	t.Cleanup(func() { hookSessionBump = previousBump })
	// The account that owns the record folder opens it again while it still
	// can: until the owner goes back.
	owned := true
	previousLchown := h.env.Lchown
	h.env.Lchown = func(path string, uid, gid int) error {
		events = append(events, "chown")
		if path == root && owned {
			owned = false
			if err := os.Chmod(root, 0o777); err != nil {
				return err
			}
		}
		return previousLchown(path, uid, gid)
	}
	t.Cleanup(func() { h.env.Lchown = previousLchown })
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []Options{{Action: ActionEnsure, PayloadDir: h.payload("1.0.1")}, {Action: ActionRepair}} {
		events, owned = nil, true
		publishHookSessionTestAllow(t, root)
		requireOK(t, h.run(opts))
		if len(events) < 3 || events[0] != "bump 777" {
			t.Fatalf("%s: the first change must be a bump: %v", opts.Action, events)
		}
		closed := false
		for _, event := range events[1:] {
			closed = closed || event == "bump 700"
			if event != "bump 700" && len(event) > 4 && event[:4] == "bump" {
				t.Fatalf("%s: every later bump must run with the folder closed: %v", opts.Action, events)
			}
		}
		if !closed {
			t.Fatalf("%s: the record folder must be bumped while closed: %v", opts.Action, events)
		}
		if hookSessionTestProves(root) {
			t.Fatalf("%s: the earlier allow must prove nothing", opts.Action)
		}
		if info, err := os.Lstat(root); err != nil || info.Mode().Perm() != 0o711 {
			t.Fatalf("%s: the folder's mode must be put back: %v %v", opts.Action, info, err)
		}
		if err := os.Chmod(root, 0o777); err != nil {
			t.Fatal(err)
		}
	}

	// A bump that cannot run fails the run, and the folder is not opened:
	// it stays closed, or the rollback gives it back the loosened mode,
	// which the hook refuses just the same.
	hookSessionBump = func(string) error { return errors.New("the volume is read-only") }
	if result := h.run(Options{Action: ActionRepair}); len(result.Errors) == 0 {
		t.Fatal("a repair whose bump fails must fail")
	}
	if info, err := os.Lstat(root); err != nil || info.Mode().Perm() != 0o700 && info.Mode().Perm()&0o022 == 0 {
		t.Fatalf("a failed bump must not open the record folder: %v %v", info, err)
	}
}
