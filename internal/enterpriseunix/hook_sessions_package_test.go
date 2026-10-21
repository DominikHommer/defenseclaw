// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

// runPostinstallTmpfiles runs packaging/linux/postinstall.sh for a package
// upgrade with stub system tools and gateway. It returns the arguments of
// each systemd-tmpfiles run, each one marked with whether it ran before the
// script's ensure.
func runPostinstallTmpfiles(t *testing.T) (runs [][]string, beforeEnsure []bool) {
	t.Helper()
	script, err := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", "postinstall.sh"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	bin, systemd, state := filepath.Join(work, "bin"), filepath.Join(work, "systemd"), filepath.Join(work, "state")
	for _, dir := range []string{bin, systemd} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	calls := filepath.Join(work, "calls")
	for _, tool := range []string{"systemd-tmpfiles", "systemd-sysusers", "systemctl", "sync"} {
		stub := "#!/bin/sh\necho \"" + tool + " $*\" >>'" + calls + "'\n"
		if tool == "systemctl" {
			stub += "[ \"$1\" != is-active ]\n"
		}
		if err := os.WriteFile(filepath.Join(bin, tool), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gateway := filepath.Join(work, "gateway")
	if err := os.WriteFile(gateway, []byte("#!/bin/sh\necho \"gateway $*\" >>'"+calls+"'\necho '{}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	text := strings.NewReplacer(
		"gateway=/opt/defenseclaw/bin/defenseclaw-gateway", "gateway="+gateway,
		"state=/var/lib/defenseclaw-enterprise", "state="+state,
		"/run/systemd/system", systemd,
		"held=/run/defenseclaw-enterprise-apply-path.held", "held="+filepath.Join(work, "held"),
	).Replace(string(script))
	cmd := exec.Command("sh", "-c", text, "postinstall.sh", "configure", "1.0.0")
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("postinstall: %v: %s", err, out)
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	ensured := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) > 3 && fields[0] == "gateway" && fields[3] == "ensure":
			ensured = true
		case len(fields) > 0 && fields[0] == "systemd-tmpfiles":
			runs = append(runs, fields[1:])
			beforeEnsure = append(beforeEnsure, !ensured)
		}
	}
	if !ensured {
		t.Fatalf("the postinstall ran no ensure: %s", data)
	}
	return runs, beforeEnsure
}

// applyPackageTmpfiles applies the package's tmpfiles.d document inside the
// fake host's root the way systemd-tmpfiles --create does for its "d"
// lines: a missing folder is created and an existing one gets the line's
// mode back. A boot-only line ("d!") is applied only with boot, as
// systemd-tmpfiles skips it without --boot. Owners are not modeled.
func applyPackageTmpfiles(t *testing.T, env *Env, boot bool) {
	t.Helper()
	document, err := systemdunits.ReadFile(systemdunits.TmpfilesName)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(document), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		kind := fields[0]
		if kind != "d" && kind != "d!" || len(fields) < 3 {
			t.Fatalf("the test models only d lines: %q", line)
		}
		if kind == "d!" && !boot {
			continue
		}
		mode, err := strconv.ParseUint(fields[2], 8, 32)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		path := env.P(fields[1])
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, os.FileMode(mode)); err != nil {
			t.Fatal(err)
		}
	}
}

// Review P1 (GAP-0352, loop round 4): a package upgrade must not restore
// trust in the record tree before the lifecycle checks it. While the record
// root was loosened, an account moved its folder away during the guardian's
// revocation and brought it back. The postinstall runs systemd-tmpfiles
// before its ensure; when the package's tmpfiles.d entry put the root back
// to 0711, the ensure found a tree the hook trusts, kept the old allow, and
// the hook accepted it during the next outage. The record tree's lines are
// boot only, so the ensure sees the loosened tree, and invalidates it.
func TestPackageUpgradeLeavesALoosenedHookSessionTreeForTheLifecycle(t *testing.T) {
	runs, beforeEnsure := runPostinstallTmpfiles(t)
	if len(runs) == 0 {
		t.Fatal("the postinstall runs systemd-tmpfiles")
	}
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	root := h.env.P(h.env.Layout.HookSessionDir)
	// The hook's rule as far as this fake host can model it: a root that
	// group or other can write is refused.
	previous := hookSessionTreeProblem
	hookSessionTreeProblem = func(path string, _ enterprisepolicy.PublishedSessionTrust) error {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or other (%04o)", path, info.Mode().Perm())
		}
		return nil
	}
	t.Cleanup(func() { hookSessionTreeProblem = previous })
	account, ok := enterprisepolicy.PublishedSessionIdentityDir(root, "1001")
	if !ok {
		t.Fatal("no account folder")
	}
	if err := os.MkdirAll(account, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(account, "copilot-p-x.json")
	if err := os.WriteFile(record, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	// The administrator loosened the root; the account moved its folder
	// away during a revocation and brought it back.
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}

	// The package upgrade: the postinstall's systemd-tmpfiles runs, then
	// its ensure.
	for i, args := range runs {
		boot := false
		for _, arg := range args {
			boot = boot || arg == "--boot"
		}
		if beforeEnsure[i] {
			applyPackageTmpfiles(t, h.env, boot)
		}
	}
	if info, err := os.Lstat(root); err != nil || info.Mode().Perm() != 0o777 {
		t.Fatalf("the package's tmpfiles run must leave the record tree for the lifecycle: %v %v", info, err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.1")}))
	if exists(record) || exists(account) {
		t.Fatal("the upgrade's ensure must invalidate the records of a tree another account could change")
	}
	if info, err := os.Lstat(root); err != nil || info.Mode().Perm() != 0o711 {
		t.Fatalf("the ensure puts the root's mode back: %v %v", info, err)
	}
}

// The boot-only lines still create the hook socket folder and the record
// root at boot, when /run is empty, with their modes.
func TestPackageTmpfilesCreateTheHookFoldersAtBoot(t *testing.T) {
	h := newTestHost(t, "linux")
	applyPackageTmpfiles(t, h.env, true)
	for path, mode := range map[string]os.FileMode{h.env.Layout.HookSocketDir: 0o755, h.env.Layout.HookSessionDir: 0o711} {
		if info, err := os.Lstat(h.env.P(path)); err != nil || !info.IsDir() || info.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", path, info, err)
		}
	}
	document, err := systemdunits.ReadFile(systemdunits.TmpfilesName)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{h.env.Layout.HookSocketDir, h.env.Layout.HookSessionDir} {
		if !strings.Contains(string(document), "\nd! "+path+" ") {
			t.Fatalf("%s must be a boot-only tmpfiles.d line", path)
		}
	}
}
