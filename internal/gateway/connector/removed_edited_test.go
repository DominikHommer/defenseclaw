// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: review fixes (G-deadcode loop round 3, after head 34b7a39da4)
// for the teardown-only connectors (removed.go). Delete with that file.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

const removedOmnigentEditedModule = removedOmnigent103Module + "\n# my change: allow the build agent\n"

// requireEditedSaved checks that the exact bytes are saved, privately, and
// listed with their step.
func (h *removedHost) requireEditedSaved(t *testing.T, c removedOnlyConnector, body string) {
	t.Helper()
	saved := c.editedCopyPath(h.dataDir, []byte(body))
	data, err := os.ReadFile(saved)
	if err != nil || string(data) != body {
		t.Fatalf("the edited module saved at %s = %q, %v; want its exact bytes %q", saved, data, err, body)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Lstat(saved); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, %v; want 0600", saved, info, err)
		}
	}
	leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
	for _, item := range leftovers {
		if item.Path == saved {
			if !strings.Contains(item.What, "your edited "+c.script) || !strings.Contains(item.Step, "copy back what you need") {
				t.Fatalf("the saved module is listed as %+v", item)
			}
			return
		}
	}
	t.Fatalf("leftovers %+v do not list the saved module %s", leftovers, saved)
}

// recordWritten records the script at the path as the one the older setup
// wrote (its post-setup hash), so the teardown does not save it.
func (h *removedHost) recordWritten(t *testing.T, c removedOnlyConnector) {
	t.Helper()
	if c.editLogical == "" {
		return
	}
	if err := captureManagedFileBackup(h.dataDir, c.name, c.editLogical, h.script(c)); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHash(h.dataDir, c.name, c.editLogical, h.script(c)); err != nil {
		t.Fatal(err)
	}
}

func (h *removedHost) editedCopies(t *testing.T, c removedOnlyConnector) []string {
	t.Helper()
	return c.editedCopies(h.dataDir)
}

// Review fix (G-deadcode loop round 3), finding 1: an OmniGent policy module
// a user edited after the 1.0.3 setup (its marker kept) was overwritten with
// the stub, under every name, and its bytes were lost: the backup record
// holds only what was there before the setup. The older teardown compared
// the module with the hash its setup recorded and kept an edited one. The
// teardown now saves the exact edited bytes (synced, read back) under
// connector_backups/omnigent before the stub replaces them, so the module
// still denies every request and the edit is not lost. An unedited module
// (its recorded hash) is not saved. A missing record, or one for another
// file, proves nothing, so the module is saved then too. A save that fails
// leaves the module and the tokens as they are; the next run finishes.
func TestRemovedTeardownSavesAnEditedOmnigentModule(t *testing.T) {
	c := removedOmnigent
	cases := map[string]struct {
		prepare   func(t *testing.T, h *removedHost)
		body      string
		wantSaved bool
	}{
		"unedited": {body: removedOmnigent103Module},
		"edited": {
			body: removedOmnigentEditedModule, wantSaved: true,
			prepare: func(t *testing.T, h *removedHost) {
				writeRemovedFile(t, h.script(c), removedOmnigentEditedModule, 0o600)
			},
		},
		"no backup record": {
			body: removedOmnigent103Module, wantSaved: true,
			prepare: func(t *testing.T, h *removedHost) {
				if err := os.Remove(managedFileBackupPath(h.dataDir, c.name, "module")); err != nil {
					t.Fatal(err)
				}
			},
		},
		"a record for another file": {
			body: removedOmnigent103Module, wantSaved: true,
			prepare: func(t *testing.T, h *removedHost) {
				other := filepath.Join(h.home, "elsewhere", c.script)
				if err := os.Remove(managedFileBackupPath(h.dataDir, c.name, "module")); err != nil {
					t.Fatal(err)
				}
				h.recordSetup(t, c.name, "module", other, "", removedOmnigent103Module)
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			if tc.prepare != nil {
				tc.prepare(t, h)
			}
			conn, _ := RetiredConnector(c.name)
			for run := 1; run <= 2; run++ {
				if err := conn.Teardown(context.Background(), h.opts); err != nil {
					t.Fatalf("Teardown run %d: %v", run, err)
				}
				h.requireStub(t, c)
				h.requireRevoked(t, c)
				copies := h.editedCopies(t, c)
				if !tc.wantSaved {
					if len(copies) != 0 {
						t.Fatalf("the unedited module was saved: %v", copies)
					}
					continue
				}
				if len(copies) != 1 {
					t.Fatalf("run %d: saved copies = %v, want exactly one", run, copies)
				}
				h.requireEditedSaved(t, c, tc.body)
			}
			if err := conn.VerifyClean(h.opts); err != nil {
				t.Fatalf("VerifyClean: %v", err)
			}
		})
	}

	// OpenHands never had the record, and its older teardown wrote its stub
	// over the script whatever its bytes: nothing is saved.
	t.Run("openhands", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, removedOpenHands)
		writeRemovedFile(t, h.script(removedOpenHands), removedOpenHands103Script+"# mine\n", 0o700)
		if err := removedOpenHands.Teardown(context.Background(), h.opts); err != nil {
			t.Fatal(err)
		}
		h.requireStub(t, removedOpenHands)
		if matches, _ := filepath.Glob(filepath.Join(h.dataDir, "connector_backups", "openhands", "*"+removedEditedInfix+"*")); len(matches) != 0 {
			t.Fatalf("an OpenHands script was saved: %v", matches)
		}
	})
}

// Finding 1's class: the edit is saved before every write that replaces
// it: the write into the file (every hard-linked name gets the stub, the
// edit is saved once), and the rename after a write into the file failed,
// which saves what is there then (an edit made after the first read too).
func TestRemovedTeardownSavesTheEditBeforeEveryWrite(t *testing.T) {
	c := removedOmnigent
	t.Run("hard links", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows renames the stub only; a hard-linked module keeps its bytes (TestRemovedTeardownWritesTheStubUnderEveryNameOfTheScript)")
		}
		h := newRemovedHost(t)
		h.stage(t, c)
		writeRemovedFile(t, h.script(c), removedOmnigentEditedModule, 0o600)
		links := h.removedHardLinks(t, c)
		first, err := os.Stat(links[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Teardown(context.Background(), h.opts); err != nil {
			t.Fatal(err)
		}
		h.requireStubUnderEveryName(t, c, first, links)
		h.requireEditedSaved(t, c, removedOmnigentEditedModule)
		if copies := h.editedCopies(t, c); len(copies) != 1 {
			t.Fatalf("saved copies = %v, want one", copies)
		}
	})
	t.Run("the rename after the write into the file failed", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, c)
		writeRemovedFile(t, h.script(c), removedOmnigentEditedModule, 0o600)
		later := removedOmnigentEditedModule + "# a later change\n"
		removedInPlaceSeams(t, func(file *os.File, data []byte, offset int64, call int) (int, error) {
			// Another change lands, then the write fails before a byte.
			if err := os.WriteFile(h.script(c), []byte(later), 0o600); err != nil {
				t.Fatal(err)
			}
			return 0, syscall.EIO
		}, nil)
		if err := c.Teardown(context.Background(), h.opts); err != nil {
			t.Fatalf("Teardown: %v", err)
		}
		h.requireStub(t, c)
		h.requireEditedSaved(t, c, removedOmnigentEditedModule)
		if runtime.GOOS != "windows" {
			// Windows never writes into the file, so the later change never
			// lands there.
			h.requireEditedSaved(t, c, later)
		}
	})
	t.Run("the write into the file saves what it reads", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, c)
		writeRemovedFile(t, h.script(c), removedOmnigentEditedModule, 0o600)
		var got []byte
		err := c.writeStubInPlace(h.script(c), func(old []byte) error {
			got = append([]byte(nil), old...)
			return errors.New("the disk is full")
		})
		if runtime.GOOS == "windows" {
			if err == nil {
				t.Fatal("Windows wrote into the file")
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), "the disk is full") || string(got) != removedOmnigentEditedModule {
			t.Fatalf("writeStubInPlace = %v, saved %q; want the save of the bytes it read to stop it", err, got)
		}
		if data, _ := os.ReadFile(h.script(c)); string(data) != removedOmnigentEditedModule {
			t.Fatalf("a failed save let the write change the module: %q", data)
		}
	})
}

// Finding 1: a save that fails leaves the edited module, under every name,
// and the tokens as they are (the module reaches the route that blocks);
// the teardown and VerifyClean fail, and the next run saves it and writes
// the stub.
func TestRemovedTeardownKeepsAnEditedModuleItCannotSave(t *testing.T) {
	c := removedOmnigent
	h := newRemovedHost(t)
	h.stage(t, c)
	writeRemovedFile(t, h.script(c), removedOmnigentEditedModule, 0o600)
	saveWrite := removedKeepEditedWrite
	t.Cleanup(func() { removedKeepEditedWrite = saveWrite })
	removedKeepEditedWrite = func(string, []byte, os.FileMode) error { return syscall.ENOSPC }
	err := c.Teardown(context.Background(), h.opts)
	if err == nil || !strings.Contains(err.Error(), "save the edited") || !strings.Contains(err.Error(), "its tokens were kept") {
		t.Fatalf("Teardown = %v, want the failed save and the tokens kept", err)
	}
	if data, _ := os.ReadFile(h.script(c)); string(data) != removedOmnigentEditedModule {
		t.Fatalf("the module it could not save was changed: %q", data)
	}
	h.requireTokensKept(t, c)
	if err := c.VerifyClean(h.opts); err == nil {
		t.Fatal("VerifyClean passed with the old module at the path")
	}
	if copies := h.editedCopies(t, c); len(copies) != 0 {
		t.Fatalf("a failed save left %v", copies)
	}
	removedKeepEditedWrite = saveWrite
	if err := c.Teardown(context.Background(), h.opts); err != nil {
		t.Fatal(err)
	}
	h.requireStub(t, c)
	h.requireRevoked(t, c)
	h.requireEditedSaved(t, c, removedOmnigentEditedModule)
}

// Review fix (G-deadcode loop round 3), finding 2: the names of the removed
// connectors stay reserved for plugins, under every spelling the teardown
// accepts, and their kept tokens are never loaded as authentication scopes.
func TestRemovedConnectorNamesStayReserved(t *testing.T) {
	r := NewDefaultRegistry()
	for _, name := range []string{"openhands", "OpenHands", "open-hands", "open_hands", " openhands", "omnigent", "OMNIGENT"} {
		err := r.RegisterPlugin(&stubConnector{name: name})
		if err == nil || !strings.Contains(err.Error(), "DefenseClaw 1.0.4 removed") {
			t.Fatalf("RegisterPlugin(%q) = %v, want it refused", name, err)
		}
		if _, ok := r.Get(name); ok {
			t.Fatalf("the refused plugin %q is in the registry", name)
		}
	}
	for _, name := range r.Names() {
		if IsRemovedConnector(name) {
			t.Fatalf("registry names %v hold the removed %q", r.Names(), name)
		}
	}

	h := newRemovedHost(t)
	for _, name := range []string{removedOpenHandsID, removedOmnigentID} {
		if _, err := EnsureHookAPIToken(h.dataDir, name); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := LoadHookAPITokens(h.dataDir, []string{"openhands", "OpenHands", "omnigent", "codex"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded["codex"]; !ok || len(loaded) != 1 {
		t.Fatalf("LoadHookAPITokens loaded scopes %v, want only codex", loaded)
	}
}
