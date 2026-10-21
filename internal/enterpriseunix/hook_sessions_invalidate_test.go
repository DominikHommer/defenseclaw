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
	"strings"
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

// hookSessionTestReachable reports whether the hook, as an agent account,
// could read account 1001's allow under root and would trust the folders on
// the way (below top: none writable by group or other or carrying a macOS
// access-list entry, every one traversable), and the allow proves the
// process.
func hookSessionTestReachable(h *testHost, root string) bool {
	h.runner.mu.Lock()
	defer h.runner.mu.Unlock()
	for dir := root; dir != h.env.Root && strings.HasPrefix(dir, h.env.Root+"/"); dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o001 == 0 || len(h.runner.acls[dir]) > 0 {
			return false
		}
	}
	return hookSessionTestProves(root)
}

// Review P2 (GAP-0352, 1.0.4 loop round 3): with a folder above the record
// folder loosened (its mode, or on macOS an access-list entry), an account
// moves the record folder, or the folder on the way to it, away before a
// repair, so the repair's first bump finds nothing, and brings it back with
// its own generation file and allow while it can still change the loosened
// folder: as soon as it can, or only once the repair has bumped the record
// folder. A repair that put the folder's mode back before it closed and
// bumped the record folder let the hook trust the old allow in between, and
// one that removed the access-list entry only after the bump let the
// account bring the old folder back after it. The repair now puts the
// folder back closed, without access-list entries, and opens it only after
// the bump: the hook reaches the old allow at no point of the run or after
// it, on Linux and macOS, for every managed folder above the record folder.
// A healthy host never has those folders closed.
func TestRepairNeverOpensAFolderAboveTheRecordsBeforeTheirBump(t *testing.T) {
	type loosening struct{ dir, how, when string }
	for _, goos := range []string{"linux", "darwin"} {
		h := newTestHost(t, goos)
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		root := h.env.P(h.env.Layout.HookSessionDir)
		above := []string{h.env.Layout.HookSocketDir}
		if goos == "darwin" {
			above = append([]string{h.env.Layout.InstallRoot}, above...)
		}
		cases := []loosening{{}}
		for _, dir := range above {
			hows := []string{"mode"}
			if goos == "darwin" {
				hows = append(hows, "acl")
			}
			for _, how := range hows {
				for _, when := range []string{"first", "after the bump"} {
					cases = append(cases, loosening{dir, how, when})
				}
			}
		}
		for _, c := range cases {
			name := goos + " healthy"
			if c.dir != "" {
				name = goos + " " + c.dir + " " + c.how + " " + c.when
			}
			t.Run(name, func(t *testing.T) {
				publishHookSessionTestAllow(t, root)
				var folder, child, away string
				if c.dir != "" {
					folder = h.env.P(c.dir)
					child = root
					for filepath.Dir(child) != folder {
						child = filepath.Dir(child)
					}
					if c.how == "mode" {
						if err := os.Chmod(folder, 0o777); err != nil {
							t.Fatal(err)
						}
					} else {
						h.runner.mu.Lock()
						h.runner.acls = map[string][]string{folder: {"user:developer allow add_subdirectory,delete_child"}}
						h.runner.mu.Unlock()
					}
					away = filepath.Join(t.TempDir(), "away")
					if err := os.Rename(child, away); err != nil {
						t.Fatal(err)
					}
				}
				writable := func() bool {
					if folder == "" {
						return false
					}
					h.runner.mu.Lock()
					acl := len(h.runner.acls[folder]) > 0
					h.runner.mu.Unlock()
					info, err := os.Lstat(folder)
					return acl || err == nil && info.Mode().Perm()&0o002 != 0
				}
				returned, bumped, reached, closedHealthy := false, false, "", ""
				probe := func(when string) {
					// On a healthy host the allow is the untouched one the
					// run's first bump ends.
					if returned && reached == "" && hookSessionTestReachable(h, root) {
						reached = when
					}
					if c.dir == "" && closedHealthy == "" {
						for _, dir := range above {
							if info, err := os.Lstat(h.env.P(dir)); err == nil && info.Mode().Perm()&0o001 == 0 {
								closedHealthy = dir + " " + when
							}
						}
					}
				}
				bringBack := func() error {
					if returned || !writable() || c.when != "first" && !bumped {
						return nil
					}
					// The account brings its old folder back while it
					// still can.
					if err := os.RemoveAll(child); err != nil {
						return err
					}
					if err := os.Rename(away, child); err != nil {
						return err
					}
					if !hookSessionTestProves(root) {
						return errors.New("the brought-back folder must still hold its own allow")
					}
					returned = true
					return nil
				}
				previousLchown := h.env.Lchown
				h.env.Lchown = func(path string, uid, gid int) error {
					if err := bringBack(); err != nil {
						return err
					}
					probe("before the chown of " + path)
					err := previousLchown(path, uid, gid)
					probe("after the chown of " + path)
					return err
				}
				t.Cleanup(func() { h.env.Lchown = previousLchown })
				previousBump := hookSessionBump
				hookSessionBump = func(path string) error {
					probe("at the bump of " + path)
					err := previousBump(path)
					bumped = bumped || path == root
					return err
				}
				t.Cleanup(func() { hookSessionBump = previousBump })
				requireOK(t, h.run(Options{Action: ActionRepair}))
				probe("after the repair")
				if c.when == "first" && !returned {
					t.Fatal("the account must bring its folder back while it can change the folder above")
				}
				if reached != "" {
					t.Fatalf("the hook could trust the old allow %s", reached)
				}
				if closedHealthy != "" {
					t.Fatalf("a healthy host must keep the folders above the records open: %s", closedHealthy)
				}
				if hookSessionTestProves(root) && returned {
					t.Fatal("the old allow must prove nothing after the repair")
				}
				h.runner.mu.Lock()
				left := len(h.runner.acls[folder])
				h.runner.mu.Unlock()
				if left > 0 {
					t.Fatalf("the repair must remove the access-list entry of %s", folder)
				}
				modes := map[string]os.FileMode{root: 0o711}
				for _, dir := range above {
					modes[h.env.P(dir)] = 0o755
				}
				for path, mode := range modes {
					if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != mode {
						t.Fatalf("%s: the mode must be put back: %v %v", path, info, err)
					}
				}
			})
		}
	}
}
