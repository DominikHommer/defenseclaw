// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: the removed OmniGent connector's teardown (removed.go) keeps
// what is not provably DefenseClaw's and verifies by the same rule.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type removedOmnigentFixture struct {
	dataDir, configPath, modulePath, pthPath string
	opts                                     SetupOpts
	notices                                  *bytes.Buffer
}

func newRemovedOmnigentFixture(t *testing.T) removedOmnigentFixture {
	t.Helper()
	home := t.TempDir()
	restoreHome, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("OMNIGENT_CONFIG_HOME", "")
	notices := &bytes.Buffer{}
	previous := removedConnectorNotices
	removedConnectorNotices = notices
	t.Cleanup(func() { removedConnectorNotices = previous })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return removedOmnigentFixture{
		dataDir:    dataDir,
		configPath: filepath.Join(home, ".omnigent", "config.yaml"),
		modulePath: filepath.Join(dataDir, "hooks", removedOmnigentModuleName+".py"),
		pthPath:    filepath.Join(t.TempDir(), "site-packages", "defenseclaw_omnigent.pth"),
		opts:       SetupOpts{DataDir: dataDir},
		notices:    notices,
	}
}

// hookToken mints the scoped hook token an older setup minted; teardown must
// revoke it once nothing of DefenseClaw's is left.
func (f removedOmnigentFixture) hookToken(t *testing.T) {
	t.Helper()
	if _, err := EnsureHookAPIToken(f.dataDir, removedOmnigentID); err != nil {
		t.Fatal(err)
	}
}

func (f removedOmnigentFixture) assertTokenRevoked(t *testing.T) {
	t.Helper()
	if token, err := LoadHookAPIToken(f.dataDir, removedOmnigentID); err != nil || token != "" {
		t.Fatalf("hook token after teardown = %q, %v; want revoked", token, err)
	}
}

func (f removedOmnigentFixture) teardownTwice(t *testing.T) {
	t.Helper()
	conn, _ := RetiredConnector(removedOmnigentID)
	for run := 1; run <= 2; run++ {
		if err := conn.Teardown(context.Background(), f.opts); err != nil {
			t.Fatalf("Teardown run %d: %v", run, err)
		}
		if err := conn.VerifyClean(f.opts); err != nil {
			t.Fatalf("VerifyClean after teardown run %d: %v", run, err)
		}
	}
}

// The policy module goes only when its bytes are provably DefenseClaw's: what
// setup recorded it last wrote or, with no recorded write, DefenseClaw's
// rendering in DefenseClaw's hook directory. A module the user changed, or
// one DefenseClaw never wrote, stays and is reported, and teardown still
// completes (the token is revoked): nothing loads the module once
// config.yaml and the .pth file no longer name it.
func TestRemovedOmnigentTeardownKeepsModuleNotProvablyOwned(t *testing.T) {
	const userModule = "def corp_policy(event):\n    return None\n"
	edited := removedOmnigentRendered + "# my local tweak\n"
	olderRendering := removedOmnigentPolicyMarker + "\n# rendered by an older release\n"
	for _, tc := range []struct {
		name string
		// before is the module setup found ("" = none); record and post say
		// whether setup recorded the backup and its own write; after is the
		// module at teardown ("" = deleted).
		before       string
		record, post bool
		after        string
		want         string // module after teardown ("" = gone)
		wantRecord   bool
		wantNotice   bool
	}{
		{name: "edited after setup created it", record: true, post: true, after: edited, want: edited, wantRecord: true, wantNotice: true},
		{name: "edited after setup replaced a module", before: userModule, record: true, post: true, after: edited, want: edited, wantRecord: true, wantNotice: true},
		{name: "unchanged, setup created it", record: true, post: true, after: removedOmnigentRendered},
		{name: "unchanged, setup replaced the user's module", before: userModule, record: true, post: true, after: removedOmnigentRendered, want: userModule},
		{name: "unchanged, setup replaced an older rendering", before: olderRendering, record: true, post: true, after: removedOmnigentRendered},
		{name: "user put their own module back", before: userModule, record: true, post: true, after: userModule, want: userModule},
		{name: "older rendering put back", before: olderRendering, record: true, post: true, after: olderRendering},
		{name: "deleted by the user", record: true, post: true},
		{name: "no record, DefenseClaw's rendering", after: removedOmnigentRendered},
		{name: "no record, not DefenseClaw's", after: userModule, want: userModule},
		{name: "setup never recorded its write", record: true, after: removedOmnigentRendered},
		{name: "setup never recorded its write over the user's module", before: userModule, record: true, after: removedOmnigentRendered, want: userModule},
		{name: "setup never recorded its write, then edited", record: true, after: userModule, want: userModule, wantRecord: true, wantNotice: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRemovedOmnigentFixture(t)
			f.hookToken(t)
			if tc.before != "" {
				writeRemovedFixture(t, f.modulePath, tc.before, 0o600)
			}
			if tc.record {
				if err := captureManagedFileBackup(f.dataDir, removedOmnigentID, "module", f.modulePath); err != nil {
					t.Fatal(err)
				}
			}
			writeRemovedFixture(t, f.modulePath, removedOmnigentRendered, 0o600)
			if tc.post {
				if err := updateManagedFileBackupPostHash(f.dataDir, removedOmnigentID, "module", f.modulePath); err != nil {
					t.Fatal(err)
				}
			}
			if tc.after == "" {
				if err := os.Remove(f.modulePath); err != nil {
					t.Fatal(err)
				}
			} else {
				writeRemovedFixture(t, f.modulePath, tc.after, 0o600)
			}

			f.teardownTwice(t)

			data, err := os.ReadFile(f.modulePath)
			switch {
			case tc.want == "" && !os.IsNotExist(err):
				t.Fatalf("module after teardown = %q, %v; want removed", data, err)
			case tc.want != "" && (err != nil || string(data) != tc.want):
				t.Fatalf("module after teardown = %q, %v; want %q", data, err, tc.want)
			}
			_, err = os.Lstat(managedFileBackupPath(f.dataDir, removedOmnigentID, "module"))
			if tc.wantRecord != (err == nil) {
				t.Fatalf("module record kept = %v, want %v", err == nil, tc.wantRecord)
			}
			if notice := f.notices.String(); tc.wantNotice != strings.Contains(notice, f.modulePath) {
				t.Fatalf("notice = %q, want one naming the module: %v", notice, tc.wantNotice)
			}
			f.assertTokenRevoked(t)
		})
	}
}

// DefenseClaw's module left behind on its own (config.yaml already clean)
// still fails verification until teardown removes it.
func TestRemovedOmnigentVerifyFailsOnOwnModule(t *testing.T) {
	f := newRemovedOmnigentFixture(t)
	writeRemovedFixture(t, f.modulePath, removedOmnigentRendered, 0o600)
	conn, _ := RetiredConnector(removedOmnigentID)
	if err := conn.VerifyClean(f.opts); err == nil || !strings.Contains(err.Error(), f.modulePath) {
		t.Fatalf("VerifyClean = %v, want the module named", err)
	}
	f.teardownTwice(t)
	if _, err := os.Lstat(f.modulePath); !os.IsNotExist(err) {
		t.Fatalf("module survived teardown: %v", err)
	}
}

// VerifyClean judges the parsed config by the rule cleanup removes entries
// with, so cleanup and verification agree: another tool's policy under
// DefenseClaw's old key, a module whose name only starts with DefenseClaw's,
// and comments are not DefenseClaw's; DefenseClaw's module or handler in any
// position is.
func TestRemovedOmnigentConfigOwnershipIsParsed(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		loads      bool
	}{
		{"foreign handler under the old key", "policies:\n  " + removedOmnigentPolicyKey + ":\n    handler: corp.check\n", false},
		{"module name prefix", "policy_modules:\n  - " + removedOmnigentModuleName + "_corp\n", false},
		{"foreign handler module prefix", "policies:\n  corp:\n    handler: " + removedOmnigentModuleName + "_corp.check\n", false},
		{"comment only", "# was " + removedOmnigentModuleName + " (" + removedOmnigentPolicyKey + ")\nserver: http://127.0.0.1:7000\n", false},
		{"quoted foreign value", "notes: \"" + removedOmnigentHandler + " was removed\"\n", false},
		{"empty", "", false},
		{"module scalar", "policy_modules: " + removedOmnigentModuleName + "\n", true},
		{"module in list", "policy_modules:\n  - corp\n  - " + removedOmnigentModuleName + "\n", true},
		{"module in flow list", "policy_modules: [corp, " + removedOmnigentModuleName + "]\n", true},
		{"handler under the old key", "policies:\n  " + removedOmnigentPolicyKey + ":\n    handler: " + removedOmnigentHandler + "\n", true},
		{"handler under another key", "policies:\n  renamed:\n    handler: " + removedOmnigentHandler + "\n", true},
		{"other function in the module", "policies:\n  corp:\n    handler: " + removedOmnigentModuleName + ".other\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeRemovedFixture(t, path, tc.body, 0o600)
			loads, err := removedOmnigentConfigLoadsPolicy(path)
			if err != nil || loads != tc.loads {
				t.Fatalf("loads = %v, %v; want %v", loads, err, tc.loads)
			}
			if err := removeRemovedOmnigentConfigEntries(path); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			after, _ := os.ReadFile(path)
			if !tc.loads && string(after) != tc.body {
				t.Fatalf("cleanup rewrote a config without DefenseClaw's entries: %q", after)
			}
			if loads, err := removedOmnigentConfigLoadsPolicy(path); err != nil || loads {
				t.Fatalf("after cleanup loads = %v, %v; want clean: %q", loads, err, after)
			}
		})
	}
	// YAML that does not parse fails verification only when it names
	// DefenseClaw's module; another tool's broken file is not DefenseClaw's.
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeRemovedFixture(t, path, "policy_modules: [corp\n", 0o600)
	if loads, err := removedOmnigentConfigLoadsPolicy(path); err != nil || loads {
		t.Fatalf("foreign unparsable config: loads = %v, %v; want clean", loads, err)
	}
	if err := removeRemovedOmnigentConfigEntries(path); err != nil {
		t.Fatalf("cleanup of a foreign unparsable config: %v", err)
	}
	writeRemovedFixture(t, path, "policy_modules: ["+removedOmnigentModuleName+"\n", 0o600)
	if _, err := removedOmnigentConfigLoadsPolicy(path); err == nil {
		t.Fatal("an unparsable config naming DefenseClaw's module verified clean")
	}
}

// End to end: a config holding another tool's policy under DefenseClaw's old
// key next to DefenseClaw's entries, and a .pth file the user added a line
// to. Teardown removes only DefenseClaw's entries and line, verification
// passes, and the scoped token is revoked.
func TestRemovedOmnigentTeardownCompletesAroundForeignState(t *testing.T) {
	f := newRemovedOmnigentFixture(t)
	f.hookToken(t)
	hookDir := filepath.Dir(f.modulePath)
	writeRemovedFixture(t, f.configPath, "policy_modules:\n  - corp\n", 0o600)
	for logical, path := range map[string]string{"config": f.configPath, "module": f.modulePath, "pth": f.pthPath} {
		if err := captureManagedFileBackup(f.dataDir, removedOmnigentID, logical, path); err != nil {
			t.Fatal(err)
		}
	}
	writeRemovedFixture(t, f.configPath, "policy_modules:\n  - corp\n  - "+removedOmnigentModuleName+
		"\npolicies:\n  "+removedOmnigentPolicyKey+":\n    handler: "+removedOmnigentHandler+"\n", 0o600)
	writeRemovedFixture(t, f.modulePath, removedOmnigentRendered, 0o600)
	writeRemovedFixture(t, f.pthPath, hookDir+"\n", 0o600)
	for logical, path := range map[string]string{"config": f.configPath, "module": f.modulePath, "pth": f.pthPath} {
		if err := updateManagedFileBackupPostHash(f.dataDir, removedOmnigentID, logical, path); err != nil {
			t.Fatal(err)
		}
	}
	// Later, another tool takes over DefenseClaw's old policy key and the
	// user adds a line to the .pth file: neither file is restorable now.
	writeRemovedFixture(t, f.configPath, "policy_modules:\n  - corp\n  - "+removedOmnigentModuleName+
		"\npolicies:\n  "+removedOmnigentPolicyKey+":\n    handler: corp.guard\n", 0o600)
	userLine := filepath.Join(filepath.Dir(f.pthPath), "corp-libs")
	writeRemovedFixture(t, f.pthPath, hookDir+"\r\n"+userLine+"\n", 0o600)

	conn, _ := RetiredConnector(removedOmnigentID)
	if err := conn.VerifyClean(f.opts); err == nil {
		t.Fatal("VerifyClean passed while config.yaml still loads DefenseClaw's module")
	}
	f.teardownTwice(t)

	config, _ := os.ReadFile(f.configPath)
	if got := string(config); strings.Contains(got, removedOmnigentModuleName) ||
		!strings.Contains(got, "corp.guard") || !strings.Contains(got, removedOmnigentPolicyKey) {
		t.Fatalf("config.yaml after teardown = %q; want only DefenseClaw's module gone", got)
	}
	pth, err := os.ReadFile(f.pthPath)
	if err != nil || string(pth) != userLine+"\n" {
		t.Fatalf(".pth after teardown = %q, %v; want only the user's line", pth, err)
	}
	if _, err := os.Lstat(f.modulePath); !os.IsNotExist(err) {
		t.Fatalf("DefenseClaw's module survived teardown: %v", err)
	}
	f.assertTokenRevoked(t)
}
