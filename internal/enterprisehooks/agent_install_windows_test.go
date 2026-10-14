// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// GAP-0226 (#1064): Entra users who installed Codex with the official
// install.ps1 got no Codex target and no machine requirements.toml, and
// status said security_complete while Codex ran without hooks.

const testCodexStandaloneRelease = "0.160.0-x86_64-pc-windows-msvc"

// writeCodexStandaloneRelease lays out one release folder as install.ps1
// writes it and returns the folder; legacy is its older platform-npm layout
// with codex.exe at the release root.
func writeCodexStandaloneRelease(t *testing.T, home, release string, legacy bool) string {
	t.Helper()
	dir := filepath.Join(windowsCodexStandaloneRoot(home), "releases", release)
	exe := filepath.Join(dir, "bin", "codex.exe")
	if legacy {
		exe = filepath.Join(dir, "codex.exe")
	}
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatalf("mkdir release: %v", err)
	}
	if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
		t.Fatalf("write codex.exe: %v", err)
	}
	return dir
}

func makeTestJunction(t *testing.T, link, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("mkdir junction parent: %v", err)
	}
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, output)
	}
}

// writeCodexStandaloneInstall writes what install.ps1 leaves for one selected
// release: the release, the current junction and the PATH bin junction.
func writeCodexStandaloneInstall(t *testing.T, home string) {
	t.Helper()
	release := writeCodexStandaloneRelease(t, home, testCodexStandaloneRelease, false)
	current := filepath.Join(windowsCodexStandaloneRoot(home), "current")
	makeTestJunction(t, current, release)
	makeTestJunction(t, windowsCodexStandaloneVisibleBin(home), filepath.Join(current, "bin"))
}

func stubUserWinGet(t *testing.T, versions map[string]map[string]string) {
	t.Helper()
	previous := windowsUserWinGetPackageVersion
	t.Cleanup(func() { windowsUserWinGetPackageVersion = previous })
	windowsUserWinGetPackageVersion = func(sid, packageID string) (string, string) {
		if version := versions[canonicalManifestTargetSID(sid)][packageID]; version != "" {
			return version, ""
		}
		return "", "no per-user WinGet package " + packageID
	}
}

func stubCodexMachinePolicyPublished(t *testing.T, published bool) {
	t.Helper()
	previous := windowsCodexMachinePolicyPublished
	t.Cleanup(func() { windowsCodexMachinePolicyPublished = previous })
	windowsCodexMachinePolicyPublished = func() bool { return published }
}

func TestStandaloneWindowsCodexDiscoveryReadsTheOfficialInstallerRelease(t *testing.T) {
	stubMachineWinGet(t, nil)
	home := t.TempDir()
	writeCodexStandaloneInstall(t, home)
	if version, reason := standaloneWindowsAgentVersionExplain(home, "codex"); version != "0.160.0" {
		t.Fatalf("install.ps1 Codex version = %q (%s), want 0.160.0", version, reason)
	}
	// The selected release wins over an npm copy: install.ps1 puts its folder
	// first on the user's PATH.
	writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@openai", "codex"), "0.150.0")
	if version, _ := standaloneWindowsAgentVersionExplain(home, "codex"); version != "0.160.0" {
		t.Fatalf("install.ps1 next to npm = %q, want the selected release 0.160.0", version)
	}

	// The older platform-npm layout keeps codex.exe at the release root.
	legacy := t.TempDir()
	release := writeCodexStandaloneRelease(t, legacy, "0.158.0-aarch64-pc-windows-msvc", true)
	makeTestJunction(t, filepath.Join(windowsCodexStandaloneRoot(legacy), "current"), release)
	if version, reason := standaloneWindowsAgentVersionExplain(legacy, "codex"); version != "0.158.0" {
		t.Fatalf("legacy layout version = %q (%s), want 0.158.0", version, reason)
	}
}

func TestStandaloneWindowsCodexDiscoveryRefusesAForeignOrIncompleteSelection(t *testing.T) {
	stubMachineWinGet(t, nil)
	home := t.TempDir()
	release := writeCodexStandaloneRelease(t, home, testCodexStandaloneRelease, false)
	releases := filepath.Dir(release)
	other := t.TempDir()
	foreign := writeCodexStandaloneRelease(t, other, testCodexStandaloneRelease, false)
	incomplete := filepath.Join(releases, "0.161.0-x86_64-pc-windows-msvc")
	if err := os.MkdirAll(incomplete, 0o755); err != nil {
		t.Fatal(err)
	}
	misnamed := filepath.Join(releases, "latest")
	if err := os.MkdirAll(filepath.Join(misnamed, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(misnamed, "bin", "codex.exe"), []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A release folder that is itself a junction to another profile's copy.
	redirected := filepath.Join(releases, "0.162.1-x86_64-pc-windows-msvc")
	makeTestJunction(t, redirected, foreign)

	previous := windowsReadInstallJunction
	t.Cleanup(func() { windowsReadInstallJunction = previous })
	for name, tc := range map[string]struct {
		target string
		err    error
		reason string
	}{
		"unreadable":  {err: errors.New("not a junction"), reason: "selects no release"},
		"foreign":     {target: foreign, reason: "outside its releases folder"},
		"misnamed":    {target: misnamed, reason: "not named <version>-<target>"},
		"no codex":    {target: incomplete, reason: "holds no codex.exe"},
		"redirected":  {target: redirected, reason: "holds no codex.exe"},
		"parent hops": {target: filepath.Join(releases, "..", "..", "..", "..", "x", testCodexStandaloneRelease), reason: "outside its releases folder"},
	} {
		t.Run(name, func(t *testing.T) {
			windowsReadInstallJunction = func(string) (string, error) { return tc.target, tc.err }
			version, reason := discoverWindowsCodexStandaloneVersion(home)
			if version != "" || !strings.Contains(reason, tc.reason) {
				t.Fatalf("version %q reason %q, want refusal containing %q", version, reason, tc.reason)
			}
		})
	}
}

func TestStandaloneWindowsDiscoveryReadsPerUserWinGetPackages(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, map[string]map[string]string{
		canonicalManifestTargetSID(testEntraUserSID): {"OpenAI.Codex": "0.160.0", "GitHub.Copilot": "1.0.40", "SST.opencode": "1.14.20"},
	})
	home := t.TempDir()
	for connector, want := range map[string]string{"codex": "0.160.0", "copilot": "1.0.40", "opencode": "1.14.20"} {
		if version, reason := standaloneWindowsAgentVersionExplainFor(testEntraUserSID, home, connector); version != want {
			t.Fatalf("%s per-user WinGet version = %q (%s), want %s", connector, version, reason, want)
		}
		// Another account's packages are not this user's.
		if version, _ := standaloneWindowsAgentVersionExplainFor(testLocalUserSID, home, connector); version != "" {
			t.Fatalf("%s for another SID = %q, want none", connector, version)
		}
	}
}

func TestReadWindowsWinGetPackageVersionTakesTheHighestValidMatch(t *testing.T) {
	path := fmt.Sprintf(`Software\DefenseClawTest\winget-%d\Uninstall`, time.Now().UnixNano())
	parent := filepath.Dir(path)
	t.Cleanup(func() {
		names := []string{"OpenAI.Codex_Microsoft.Winget.Source_8wekyb3d8bbwe", "OpenAI.Codex_other", "OpenAI.CodexPreview_x", "OpenAI.Codex_bad"}
		for _, name := range names {
			_ = registry.DeleteKey(registry.CURRENT_USER, path+`\`+name)
		}
		_ = registry.DeleteKey(registry.CURRENT_USER, path)
		_ = registry.DeleteKey(registry.CURRENT_USER, parent)
		_ = registry.DeleteKey(registry.CURRENT_USER, filepath.Dir(parent))
	})
	for name, version := range map[string]string{
		"OpenAI.Codex_Microsoft.Winget.Source_8wekyb3d8bbwe": "0.159.0",
		"OpenAI.Codex_other":    "0.160.0",
		"OpenAI.CodexPreview_x": "9.9.9",
		"OpenAI.Codex_bad":      "9.9.9\nforged",
	} {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, path+`\`+name, registry.ALL_ACCESS)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if err := key.SetStringValue("DisplayVersion", version); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
		_ = key.Close()
	}
	if version, ok := readWindowsWinGetPackageVersion(registry.CURRENT_USER, path, 0, windowsWinGetUserMaxSubKeys, "OpenAI.Codex"); !ok || version != "0.160.0" {
		t.Fatalf("version = %q ok=%t, want 0.160.0 (prefix match, control characters refused)", version, ok)
	}
	if version, ok := readWindowsWinGetPackageVersion(registry.CURRENT_USER, path, 0, windowsWinGetUserMaxSubKeys, "GitHub.Copilot"); ok || version != "" {
		t.Fatalf("absent package = %q ok=%t", version, ok)
	}
}

func TestEnumerateWindowsStandaloneEnrollsAnInstallerCodexForEntraAndLocalUsers(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	entra, local := t.TempDir(), t.TempDir()
	writeCodexStandaloneInstall(t, entra)
	writeCodexStandaloneInstall(t, local)
	injectWindowsProfileList(t, map[string]string{testEntraUserSID: entra, testLocalUserSID: local})
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 2 {
		t.Fatalf("targets = %+v, want a Codex row for the Entra and the local user", manifest.Targets)
	}
	for _, target := range manifest.Targets {
		if target.Connector != "codex" || target.AgentVersion != "0.160.0" || target.Enabled == nil || !*target.Enabled || !target.Deferred {
			t.Fatalf("row %+v, want an enabled deferred codex row at 0.160.0", target)
		}
	}
	if len(reported) != 0 {
		t.Fatalf("unprotected = %+v, want none", reported)
	}
}

func TestEnumerateWindowsStandaloneReportsAnInstalledCodexItCannotRead(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	stubCodexMachinePolicyPublished(t, false)
	home := t.TempDir()
	// install.ps1's older layout: codex.exe copied into the PATH folder, no
	// release record.
	bin := windowsCodexStandaloneVisibleBin(home)
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "codex.exe"), []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	injectWindowsProfileList(t, map[string]string{testEntraUserSID: home})
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 0 {
		t.Fatalf("targets = %+v, want none for an unreadable version", manifest.Targets)
	}
	if len(reported) != 1 || reported[0].Connector != "codex" || reported[0].SID != canonicalManifestTargetSID(testEntraUserSID) {
		t.Fatalf("unprotected = %+v, want the Entra user's codex", reported)
	}
	message := reported[0].Message()
	for _, want := range []string{bin, "version could not be read", "npm install -g @openai/codex", "requirements.toml is not published"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message %q does not contain %q", message, want)
		}
	}
}
