// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// A Cursor guard rebuild snapshots its artifacts when the transaction starts,
// but Cursor and administrators do not take the DefenseClaw lock. Before it
// writes a file the rebuild reads it again: an administrator's hooks.json edit
// made in between is kept (the registration is merged into it, or the rebuild
// stops when it cannot carry the guard), a concurrent change to a file
// DefenseClaw owns stops the rebuild, and a rollback never puts a preimage
// back over a file that changed after the rebuild wrote it.
func TestWindowsCursorMachineGuardRebuildKeepsConcurrentChanges(t *testing.T) {
	const hook = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	adminHooks := []byte(`{"version":1,"hooks":{"adminEvent":[{"type":"command","command":"admin-concurrent-hook"}]}}`)
	type files struct{ hooks, adapter, state, receipt []byte }
	read := func(t *testing.T, paths windowsCursorPaths) files {
		t.Helper()
		var result files
		for path, target := range map[string]*[]byte{paths.Hooks: &result.hooks, paths.Adapter: &result.adapter, paths.State: &result.state, paths.Receipt: &result.receipt} {
			data, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			*target = data
		}
		return result
	}
	write := func(t *testing.T, path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// beforeWrite runs edit once, just before the rebuild re-reads path.
	beforeWrite := func(t *testing.T, path string, edit func()) {
		t.Helper()
		previous := windowsCursorManagedGuardRebuildBeforeWrite
		done := false
		windowsCursorManagedGuardRebuildBeforeWrite = func(target string) {
			if !done && strings.EqualFold(target, path) {
				done = true
				edit()
			}
		}
		t.Cleanup(func() { windowsCursorManagedGuardRebuildBeforeWrite = previous })
	}
	failOpen := func(t *testing.T, paths windowsCursorPaths) {
		data, err := os.ReadFile(paths.Hooks)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		events, _ := document["hooks"].(map[string]any)
		for _, raw := range events {
			entries, _ := raw.([]any)
			for _, entry := range entries {
				if hookEntry, ok := entry.(map[string]any); ok && hookEntry["failClosed"] == true {
					hookEntry["failClosed"] = false
				}
			}
		}
		edited, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		write(t, paths.Hooks, edited)
	}
	hooksDamage := []struct {
		name  string
		apply func(t *testing.T, paths windowsCursorPaths)
	}{
		{"hooks.json missing", func(t *testing.T, paths windowsCursorPaths) {
			if err := os.Remove(paths.Hooks); err != nil {
				t.Fatal(err)
			}
		}},
		{"hooks.json replaced", func(t *testing.T, paths windowsCursorPaths) {
			write(t, paths.Hooks, []byte(`{"version":1,"hooks":{"operatorEvent":[{"type":"command","command":"operator-hook"}]}}`))
		}},
		{"registration fails open", failOpen},
		{"hooks.json not JSON", func(t *testing.T, paths windowsCursorPaths) {
			write(t, paths.Hooks, []byte("{ not json"))
		}},
	}
	for _, enrolled := range []bool{false, true} {
		for _, hooksCase := range hooksDamage {
			for _, removeAdapter := range []bool{false, true} {
				name := map[bool]string{false: "empty", true: "Alice"}[enrolled] + "/" + hooksCase.name +
					map[bool]string{false: "/adapter intact", true: "/adapter missing"}[removeAdapter]
				t.Run("administrator edit is kept/"+name, func(t *testing.T) {
					paths := installWindowsCursorStandaloneGuardForTest(t, hook, enrolled)
					targetsBefore, _, err := ReadWindowsCursorManagedPolicyTargets()
					if err != nil {
						t.Fatal(err)
					}
					hooksCase.apply(t, paths)
					if removeAdapter {
						if err := os.Remove(paths.Adapter); err != nil {
							t.Fatal(err)
						}
					}
					beforeWrite(t, paths.Hooks, func() { write(t, paths.Hooks, adminHooks) })
					restored, err := RestoreWindowsCursorManagedAdapter(hook)
					if err != nil || !restored {
						t.Fatalf("rebuild: restored=%t err=%v", restored, err)
					}
					hooksAfter, err := os.ReadFile(paths.Hooks)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Contains(hooksAfter, []byte("admin-concurrent-hook")) {
						t.Fatalf("the rebuild discarded the administrator's concurrent hooks.json edit: %s", hooksAfter)
					}
					if err := connector.VerifyWindowsCursorEnterpriseHooks(hooksAfter, paths.Adapter, "closed"); err != nil {
						t.Fatalf("rebuilt registration is not the closed guard: %v", err)
					}
					targets, active, err := ReadWindowsCursorManagedPolicyTargets()
					if err != nil || !active || !slices.Equal(targets, targetsBefore) {
						t.Fatalf("rebuilt guard: active=%t targets=%v (want %v) err=%v", active, targets, targetsBefore, err)
					}
				})
			}
		}
	}

	t.Run("administrator attribute change is kept", func(t *testing.T) {
		paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
		hooksDamage[1].apply(t, paths)
		beforeWrite(t, paths.Hooks, func() {
			pointer, err := windows.UTF16PtrFromString(paths.Hooks)
			if err != nil {
				t.Fatal(err)
			}
			attributes, err := windows.GetFileAttributes(pointer)
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetFileAttributes(pointer, attributes|windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED); err != nil {
				t.Fatal(err)
			}
		})
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
			t.Fatalf("rebuild: restored=%t err=%v", restored, err)
		}
		pointer, err := windows.UTF16PtrFromString(paths.Hooks)
		if err != nil {
			t.Fatal(err)
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err != nil {
			t.Fatal(err)
		}
		if attributes&windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED == 0 {
			t.Fatal("the rebuild put back the snapshot's attributes over the administrator's concurrent change")
		}
		if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
			t.Fatalf("rebuilt guard: active=%t err=%v", active, err)
		}
	})

	t.Run("administrator edit that is not JSON stops the rebuild", func(t *testing.T) {
		paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
		for _, path := range []string{paths.Hooks, paths.Adapter} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		before := read(t, paths)
		partial := []byte(`{"version":1,"hooks":{"adminEvent":[`)
		beforeWrite(t, paths.Hooks, func() { write(t, paths.Hooks, partial) })
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err == nil || restored {
			t.Fatalf("rebuild over a concurrent invalid edit: restored=%t err=%v", restored, err)
		}
		after := read(t, paths)
		if !bytes.Equal(after.hooks, partial) {
			t.Fatalf("the rebuild replaced the administrator's concurrent hooks.json: %q", after.hooks)
		}
		if !bytes.Equal(after.adapter, before.adapter) || !bytes.Equal(after.state, before.state) || !bytes.Equal(after.receipt, before.receipt) {
			t.Fatal("a stopped rebuild left a partly rebuilt guard")
		}
	})

	t.Run("rollback keeps an edit made after the hooks.json write", func(t *testing.T) {
		paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
		for _, path := range []string{paths.Hooks, paths.Adapter} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		before := read(t, paths)
		writer := windowsManagedPolicyWriter
		edited := false
		windowsManagedPolicyWriter = func(path string, data []byte, userReadable bool) error {
			if err := writer(path, data, userReadable); err != nil {
				return err
			}
			if !edited && strings.EqualFold(path, paths.Hooks) {
				edited = true
				// The administrator saves over the rebuilt file before the
				// rebuild validates it.
				write(t, paths.Hooks, adminHooks)
			}
			return nil
		}
		t.Cleanup(func() { windowsManagedPolicyWriter = writer })
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err == nil || restored {
			t.Fatalf("rebuild overtaken by a concurrent edit: restored=%t err=%v", restored, err)
		}
		after := read(t, paths)
		if !bytes.Equal(after.hooks, adminHooks) {
			t.Fatalf("the rollback discarded the administrator's concurrent hooks.json: %q", after.hooks)
		}
		if after.adapter != nil || !bytes.Equal(after.state, before.state) || !bytes.Equal(after.receipt, before.receipt) {
			t.Fatal("the rollback did not put back the rebuilt adapter")
		}
		windowsManagedPolicyWriter = writer
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
			t.Fatalf("rebuild after the concurrent edit: restored=%t err=%v", restored, err)
		}
		hooksAfter, err := os.ReadFile(paths.Hooks)
		if err != nil || !bytes.Contains(hooksAfter, []byte("admin-concurrent-hook")) {
			t.Fatalf("the next rebuild lost the administrator's hook: %v", err)
		}
	})

	t.Run("concurrent change to an owned artifact stops the rebuild", func(t *testing.T) {
		paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
		for _, path := range []string{paths.Hooks, paths.Adapter} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		concurrent := []byte("exit 0\r\n")
		beforeWrite(t, paths.Adapter, func() { write(t, paths.Adapter, concurrent) })
		if restored, err := RestoreWindowsCursorManagedAdapter(hook); err == nil || restored {
			t.Fatalf("rebuild over a concurrent adapter: restored=%t err=%v", restored, err)
		}
		after := read(t, paths)
		if !bytes.Equal(after.adapter, concurrent) || after.hooks != nil {
			t.Fatalf("the rebuild wrote over a concurrent change: adapter=%q hooks=%q", after.adapter, after.hooks)
		}
	})
}
