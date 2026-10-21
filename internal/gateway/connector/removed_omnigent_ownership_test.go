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
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// YAML anchors, aliases and merge keys reach DefenseClaw's entries in an
// edited config. Cleanup follows them: an entry that loads DefenseClaw's
// handler through an alias or a merge goes too, an alias left naming a
// removed anchor becomes a copy of it, and the written file always parses.
func TestRemovedOmnigentConfigCleanupFollowsYAMLAliases(t *testing.T) {
	const handler = removedOmnigentHandler
	for _, tc := range []struct {
		name, body string
		keep       []string // must survive cleanup
		gone       []string // must not
	}{
		{
			name: "policy alias of the anchored policy",
			body: "policies:\n  " + removedOmnigentPolicyKey + ": &dc\n    handler: " + handler + "\n  copy: *dc\n  corp:\n    handler: corp.check\n",
			keep: []string{"corp.check"}, gone: []string{"copy", removedOmnigentPolicyKey},
		},
		{
			name: "anchored policy aliased outside policies",
			body: "policies:\n  " + removedOmnigentPolicyKey + ": &dc\n    handler: " + handler + "\n    timeout: 5\n  corp:\n    handler: corp.check\nx-saved: *dc\n",
			keep: []string{"corp.check", "x-saved", "timeout: 5"},
		},
		{
			name: "policy merging the anchored policy",
			body: "policies:\n  " + removedOmnigentPolicyKey + ": &dc\n    handler: " + handler + "\n  inherits:\n    <<: *dc\n    timeout: 3\n  corp:\n    handler: corp.check\n",
			keep: []string{"corp.check"}, gone: []string{"inherits"},
		},
		{
			name: "policy merging the anchored policy with its own handler",
			body: "policies:\n  " + removedOmnigentPolicyKey + ": &dc\n    handler: " + handler + "\n    timeout: 9\n  override:\n    <<: *dc\n    handler: corp.other\n",
			keep: []string{"override", "corp.other", "timeout: 9"},
		},
		{
			name: "module listed through an alias",
			body: "x-module: &m " + removedOmnigentModuleName + "\npolicy_modules: [corp, *m]\n",
			keep: []string{"corp", "x-module"},
		},
		{
			name: "anchored module aliased elsewhere",
			body: "policy_modules:\n  - corp\n  - &m " + removedOmnigentModuleName + "\nx-note: *m\n",
			keep: []string{"corp", "x-note"},
		},
		{
			name: "module list through an alias",
			body: "x-modules: &mods [corp, " + removedOmnigentModuleName + "]\npolicy_modules: *mods\n",
			keep: []string{"corp", "policy_modules"},
		},
		{
			name: "handler through an alias",
			body: "x-handler: &h " + handler + "\npolicies:\n  renamed:\n    handler: *h\n  corp:\n    handler: corp.check\n",
			keep: []string{"corp.check", "x-handler"}, gone: []string{"renamed"},
		},
		{
			name: "policies through an alias",
			body: "x-policies: &p\n  dc:\n    handler: " + handler + "\n  corp:\n    handler: corp.check\npolicies: *p\n",
			keep: []string{"corp.check", "policies"}, gone: []string{"dc:"},
		},
		{
			name: "nested anchor inside the removed policy",
			body: "policies:\n  " + removedOmnigentPolicyKey + ":\n    handler: " + handler + "\n    limits: &limits {calls: 3}\n  corp:\n    handler: corp.check\n    limits: *limits\n",
			keep: []string{"corp.check", "calls: 3"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeRemovedFixture(t, path, tc.body, 0o600)
			if loads, err := removedOmnigentConfigLoadsPolicy(path); err != nil || !loads {
				t.Fatalf("before cleanup loads = %v, %v; want DefenseClaw's policy found", loads, err)
			}
			if err := removeRemovedOmnigentConfigEntries(path); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var parsed interface{}
			if err := yaml.Unmarshal(after, &parsed); err != nil {
				t.Fatalf("cleaned config no longer parses: %v\n%s", err, after)
			}
			if loads, err := removedOmnigentConfigLoadsPolicy(path); err != nil || loads {
				t.Fatalf("after cleanup loads = %v, %v; want clean:\n%s", loads, err, after)
			}
			if removedOmnigentValueLoadsPolicy(parsed) {
				t.Fatalf("the loaded value still names DefenseClaw's policy:\n%s", after)
			}
			for _, want := range tc.keep {
				if !strings.Contains(string(after), want) {
					t.Fatalf("cleanup dropped %q:\n%s", want, after)
				}
			}
			for _, unwanted := range tc.gone {
				if strings.Contains(string(after), unwanted) {
					t.Fatalf("cleanup kept %q:\n%s", unwanted, after)
				}
			}
		})
	}
}

// A config that would still load DefenseClaw's policy after the edit cleanup
// can make (here a root merge key brings policy_modules in) is refused and
// left byte for byte; teardown then keeps the policy module, so OmniGent can
// still import what its config names, and reports the config.
func TestRemovedOmnigentTeardownKeepsModuleWhileConfigCannotBeCleaned(t *testing.T) {
	merged := "x-base: &base\n  policy_modules: [" + removedOmnigentModuleName + "]\n<<: *base\n"
	for name, body := range map[string]string{
		"merge only":               merged,
		"merge and a direct entry": merged + "policies:\n  " + removedOmnigentPolicyKey + ":\n    handler: " + removedOmnigentHandler + "\n",
	} {
		t.Run(name, func(t *testing.T) { testRemovedOmnigentKeepsModuleForConfig(t, body) })
	}
}

func testRemovedOmnigentKeepsModuleForConfig(t *testing.T, body string) {
	f := newRemovedOmnigentFixture(t)
	writeRemovedFixture(t, f.configPath, body, 0o600)
	writeRemovedFixture(t, f.modulePath, removedOmnigentRendered, 0o600)
	if loads, err := removedOmnigentConfigLoadsPolicy(f.configPath); err != nil || !loads {
		t.Fatalf("merged policy_modules not found: %v, %v", loads, err)
	}
	conn, _ := RetiredConnector(removedOmnigentID)
	if err := conn.Teardown(context.Background(), f.opts); err == nil || !strings.Contains(err.Error(), "by hand") {
		t.Fatalf("Teardown = %v; want the config refused", err)
	}
	if got, _ := os.ReadFile(f.configPath); string(got) != body {
		t.Fatalf("a config cleanup could not finish was rewritten:\n%s", got)
	}
	if _, err := os.Lstat(f.modulePath); err != nil {
		t.Fatalf("the policy module went while config.yaml still names it: %v", err)
	}
	if err := conn.VerifyClean(f.opts); err == nil {
		t.Fatal("VerifyClean passed while config.yaml still loads DefenseClaw's module")
	}
}

// A config.yaml teardown cannot write keeps the policy module it names; once
// the file is writable a later run finishes.
func TestRemovedOmnigentTeardownKeepsModuleWhileConfigIsReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX directory permissions that bind the caller")
	}
	f := newRemovedOmnigentFixture(t)
	writeRemovedFixture(t, f.configPath, "policy_modules:\n  - corp\n  - "+removedOmnigentModuleName+"\n", 0o600)
	writeRemovedFixture(t, f.modulePath, removedOmnigentRendered, 0o600)
	configDir := filepath.Dir(f.configPath)
	if err := os.Chmod(configDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(configDir, 0o700) })
	conn, _ := RetiredConnector(removedOmnigentID)
	if err := conn.Teardown(context.Background(), f.opts); err == nil {
		t.Fatal("Teardown succeeded with a read-only OmniGent config directory")
	}
	if _, err := os.Lstat(f.modulePath); err != nil {
		t.Fatalf("the policy module went while config.yaml still names it: %v", err)
	}
	if err := os.Chmod(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.teardownTwice(t)
	if _, err := os.Lstat(f.modulePath); !os.IsNotExist(err) {
		t.Fatalf("the policy module survived the retry: %v", err)
	}
}

// A key set twice in one mapping leaves which copy OmniGent uses up to its
// YAML loader. Cleanup must not guess: removing a policy whose later handler
// is another tool's would switch that policy off, and passing a file whose
// effective entry is DefenseClaw's would remove the module OmniGent still
// imports. Every such config naming DefenseClaw's module fails verification
// and is left byte for byte; a file that never names the module is not
// DefenseClaw's and stays clean.
func TestRemovedOmnigentConfigCleanupRefusesDuplicateKeys(t *testing.T) {
	const handler = removedOmnigentHandler
	for _, tc := range []struct{ name, body string }{
		{"handler set twice, ours first", "policies:\n  guard:\n    handler: " + handler + "\n    handler: corp_policy.check\n"},
		{"handler set twice, ours last", "policies:\n  guard:\n    handler: corp_policy.check\n    handler: " + handler + "\n"},
		{"handler set twice, quoted key", "policies:\n  guard:\n    handler: " + handler + "\n    \"handler\": corp_policy.check\n"},
		{"policy name set twice, ours first", "policies:\n  guard:\n    handler: " + handler + "\n  guard:\n    handler: corp_policy.check\n"},
		{"policy name set twice, ours last", "policies:\n  guard:\n    handler: corp_policy.check\n  guard:\n    handler: " + handler + "\n"},
		{"policies set twice", "policies:\n  dc:\n    handler: " + handler + "\npolicies:\n  corp:\n    handler: corp_policy.check\n"},
		{"policy_modules set twice", "policy_modules: [" + removedOmnigentModuleName + "]\npolicy_modules: [corp]\n"},
		{"merge key set twice", "x-dc: &dc {handler: " + handler + "}\nx-corp: &corp {handler: corp_policy.check}\npolicies:\n  guard:\n    <<: *dc\n    <<: *corp\n"},
		{"handler set twice in a merge source", "x-base: &base\n  handler: " + handler + "\n  handler: corp_policy.check\npolicies:\n  guard:\n    <<: *base\n"},
		{"root merge plus an unrelated key set twice", "x-base: &base\n  policy_modules: [" + removedOmnigentModuleName + "]\n<<: *base\nlog_level: info\nlog_level: debug\n"},
		{"unrelated key set twice next to our policy", "policies:\n  dc:\n    handler: " + handler + "\n  corp:\n    handler: corp_policy.check\n    timeout: 1\n    timeout: 2\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeRemovedFixture(t, path, tc.body, 0o600)
			if loads, err := removedOmnigentConfigLoadsPolicy(path); err == nil {
				t.Fatalf("loads = %v with no error; want a config with a key set twice refused", loads)
			}
			if err := removeRemovedOmnigentConfigEntries(path); err == nil || !strings.Contains(err.Error(), "by hand") {
				t.Fatalf("cleanup = %v; want it refused", err)
			}
			if got, _ := os.ReadFile(path); string(got) != tc.body {
				t.Fatalf("cleanup rewrote a config with a key set twice:\n%s", got)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	foreign := "policies:\n  guard:\n    handler: corp_policy.a\n    handler: corp_policy.b\n"
	writeRemovedFixture(t, path, foreign, 0o600)
	if loads, err := removedOmnigentConfigLoadsPolicy(path); err != nil || loads {
		t.Fatalf("foreign config with a key set twice: loads = %v, %v; want clean", loads, err)
	}
	if err := removeRemovedOmnigentConfigEntries(path); err != nil {
		t.Fatalf("cleanup of a foreign config with a key set twice: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != foreign {
		t.Fatalf("cleanup rewrote a foreign config:\n%s", got)
	}
}

// End to end for the reported case: a user appended their own handler to
// DefenseClaw's old policy. Teardown fails without touching config.yaml,
// keeps the module, the backups and the token for the retry, and once the
// user fixes the file the next run finishes and keeps their policy.
func TestRemovedOmnigentTeardownKeepsStateForDuplicateHandler(t *testing.T) {
	f := newRemovedOmnigentFixture(t)
	f.hookToken(t)
	body := "policy_modules:\n  - corp_policy\n  - " + removedOmnigentModuleName + "\npolicies:\n  " +
		removedOmnigentPolicyKey + ":\n    handler: " + removedOmnigentHandler + "\n    handler: corp_policy.check\n"
	writeRemovedFixture(t, f.configPath, body, 0o600)
	writeRemovedFixture(t, f.modulePath, removedOmnigentRendered, 0o600)
	conn, _ := RetiredConnector(removedOmnigentID)
	for run := 1; run <= 2; run++ {
		if err := conn.Teardown(context.Background(), f.opts); err == nil || !strings.Contains(err.Error(), "by hand") {
			t.Fatalf("Teardown run %d = %v; want the config refused", run, err)
		}
		if got, _ := os.ReadFile(f.configPath); string(got) != body {
			t.Fatalf("Teardown run %d rewrote config.yaml:\n%s", run, got)
		}
		if _, err := os.Lstat(f.modulePath); err != nil {
			t.Fatalf("the policy module went while config.yaml still names it: %v", err)
		}
		if err := conn.VerifyClean(f.opts); err == nil {
			t.Fatal("VerifyClean passed on a config with the handler set twice")
		}
		if token, err := LoadHookAPIToken(f.dataDir, removedOmnigentID); err != nil || token == "" {
			t.Fatalf("hook token = %q, %v; want it kept for the retry", token, err)
		}
	}
	// The user drops DefenseClaw's line; the retry finishes.
	writeRemovedFixture(t, f.configPath, "policy_modules:\n  - corp_policy\n  - "+removedOmnigentModuleName+
		"\npolicies:\n  "+removedOmnigentPolicyKey+":\n    handler: corp_policy.check\n", 0o600)
	f.teardownTwice(t)
	config, _ := os.ReadFile(f.configPath)
	if got := string(config); strings.Contains(got, removedOmnigentModuleName) || !strings.Contains(got, "corp_policy.check") {
		t.Fatalf("config.yaml after the retry = %q; want only DefenseClaw's module gone", got)
	}
	if _, err := os.Lstat(f.modulePath); !os.IsNotExist(err) {
		t.Fatalf("DefenseClaw's module survived the retry: %v", err)
	}
	f.assertTokenRevoked(t)
}
