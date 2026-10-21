// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A redirected AppData folder is read only when it is a folder the account
// owns, reached without a junction; a missing one is skipped quietly
// (GAP-1249).
func TestRedirectedAppDataFolderMustBeOwnedAndReachedWithoutAJunction(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "Redirected", "alice", "Roaming")
	other := filepath.Join(root, "Users", "bob", "AppData", "Roaming")
	for _, dir := range []string{folder, other, filepath.Join(root, "Users", "carol", "AppData", "Roaming")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	junction := func(link, target string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
		}
	}
	sd, err := windows.GetNamedSecurityInfo(folder, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ownerSID, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	owner := ownerSID.String()
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	refused := func(sid, path, reason string) {
		t.Helper()
		logged = nil
		if got := windowsUsableIDEAppDataFolder(sid, path, logf); got != "" {
			t.Errorf("%s is read for %s, want refused (%s)", path, sid, reason)
		}
		if len(logged) != 1 || !strings.Contains(logged[0], reason) {
			t.Errorf("%s: logged %q, want %q", path, logged, reason)
		}
	}
	if got := windowsUsableIDEAppDataFolder(owner, folder, logf); got != folder {
		t.Fatalf("the owner's own folder = %q, want %q (logged %q)", got, folder, logged)
	}
	refused("S-1-5-21-1000000001-1000000002-1000000003-1001", folder, "the account does not own it")
	// The folder replaced by a junction to another profile's folder, which
	// the same account owns.
	swapped := filepath.Join(root, "Redirected", "alice", "Roaming2")
	junction(swapped, other)
	refused(owner, swapped, "a link or junction leads to it")
	// A junction above the folder.
	junction(filepath.Join(root, "Redirected", "carol"), filepath.Join(root, "Users", "carol"))
	refused(owner, filepath.Join(root, "Redirected", "carol", "AppData", "Roaming"), "a link or junction leads to it")
	file := filepath.Join(root, "Redirected", "alice", "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	refused(owner, file, "it is not a folder")
	logged = nil
	if got := windowsUsableIDEAppDataFolder(owner, filepath.Join(root, "Redirected", "dave", "Roaming"), logf); got != "" || len(logged) != 0 {
		t.Errorf("a missing folder = %q, logged %q; want skipped quietly", got, logged)
	}
}
