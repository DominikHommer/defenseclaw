// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Standalone discovery of the agent installs that keep no package.json for
// the fixed probes (GAP-0226, #1064):
//
//   - The official Codex installer, install.ps1
//     (https://chatgpt.com/codex/install.ps1), unpacks each release into
//     %USERPROFILE%\.codex\packages\standalone\releases\<version>-<target>,
//     points the junction ...\standalone\current at the selected release,
//     and points the junction %LOCALAPPDATA%\Programs\OpenAI\Codex\bin, which
//     it puts first on the user's PATH, at current\bin.
//   - A per-user WinGet package (winget install without --scope machine)
//     records its version in the user's own uninstall registry, readable
//     while the user's hive is loaded (the user is signed in).
//
// Neither was read, so a host whose users installed Codex with install.ps1
// got no Codex target and no machine requirements.toml, Codex ran without
// DefenseClaw hooks, and status and verify still said security_complete.
// Every read here is static and bounded and follows no junction: only the
// name the current junction points at is read. The values are the user's own
// claims, like a package.json version: they select a hook contract, and a
// falsified one can at most keep that user's row from enrolling, which the
// enumerator reports.

// windowsCodexStandaloneReleaseName matches install.ps1's release folder
// "<version>-<target>", with the versions its Assert-ValidReleaseVersion
// admits and the two Windows targets it installs.
var windowsCodexStandaloneReleaseName = regexp.MustCompile(
	`^([0-9]+\.[0-9]+\.[0-9]+(?:-alpha(?:\.[0-9]+){0,2}|-beta(?:\.[0-9]+)?)?)-(?:x86_64|aarch64)-pc-windows-msvc$`)

// windowsReadInstallJunction reads a junction's target without following it;
// tests replace it.
var windowsReadInstallJunction = os.Readlink

// windowsCodexStandaloneRoot is install.ps1's per-user install root. The
// installer moves it under CODEX_HOME when that is set; such a root is found
// by its PATH folder (windowsCodexStandaloneVisibleBin) and reported.
func windowsCodexStandaloneRoot(profileHome string) string {
	return filepath.Join(profileHome, ".codex", "packages", "standalone")
}

// windowsCodexStandaloneVisibleBin is the folder install.ps1 puts on the
// user's PATH.
func windowsCodexStandaloneVisibleBin(profileHome string) string {
	return filepath.Join(profileHome, "AppData", "Local", "Programs", "OpenAI", "Codex", "bin")
}

// discoverWindowsCodexStandaloneVersion reads the version of the Codex
// release install.ps1 selected for this profile: the name of the release
// folder its current junction points at, which must sit directly in this
// profile's releases folder and hold codex.exe through a plain folder chain.
func discoverWindowsCodexStandaloneVersion(profileHome string) (string, string) {
	root := windowsCodexStandaloneRoot(profileHome)
	releases := filepath.Join(root, "releases")
	if err := winpath.RejectReparseChain(releases); err != nil {
		return "", "the Codex standalone install folder has a refused reparse chain"
	}
	releasesInfo, err := os.Lstat(releases)
	if err != nil || !releasesInfo.IsDir() {
		return "", "no Codex standalone install under this profile"
	}
	target, err := windowsReadInstallJunction(filepath.Join(root, "current"))
	if err != nil || strings.TrimSpace(target) == "" {
		return "", "the Codex standalone install selects no release (its current junction is missing or unreadable)"
	}
	target = filepath.Clean(strings.TrimSpace(target))
	// Compared by identity, not by spelling: the junction may name the
	// folder in a long or short (8.3) form.
	if parent, err := os.Lstat(filepath.Dir(target)); err != nil || !os.SameFile(parent, releasesInfo) {
		return "", "the Codex standalone current junction points outside its releases folder"
	}
	match := windowsCodexStandaloneReleaseName.FindStringSubmatch(filepath.Base(target))
	if match == nil || !isValidWindowsAgentVersion(match[1]) {
		return "", "the Codex standalone current release is not named <version>-<target>"
	}
	if !windowsCodexStandaloneReleaseHasCLI(target) {
		return "", "the Codex standalone current release holds no codex.exe"
	}
	return match[1], ""
}

// windowsCodexStandaloneReleaseHasCLI reports a regular codex.exe reached
// through a plain folder chain: bin\codex.exe in install.ps1's package
// layout, codex.exe in its older platform-npm layout.
func windowsCodexStandaloneReleaseHasCLI(release string) bool {
	for _, candidate := range []string{
		filepath.Join(release, "bin", "codex.exe"),
		filepath.Join(release, "codex.exe"),
	} {
		if winpath.RejectReparseChain(candidate) != nil {
			continue
		}
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// windowsWinGetUserUninstallKey is a user's own uninstall root under
// HKEY_USERS\<SID>, where WinGet records a per-user package as
// "<PackageIdentifier>_<SourceIdentifier>" with its DisplayVersion.
const windowsWinGetUserUninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

// windowsWinGetUserMaxSubKeys bounds the listing of that user-writable key.
const windowsWinGetUserMaxSubKeys = 2048

// windowsUserWinGetPackageVersion is the registry seam for per-user WinGet
// discovery so tests do not depend on loaded user hives.
var windowsUserWinGetPackageVersion = readWindowsUserWinGetPackageVersion

// readWindowsUserWinGetPackageVersion returns the DisplayVersion of the
// per-user WinGet package packageID of account sid.
func readWindowsUserWinGetPackageVersion(sid, packageID string) (string, string) {
	sid = canonicalManifestTargetSID(sid)
	if sid == "" {
		return "", ""
	}
	if version, ok := readWindowsWinGetPackageVersion(registry.USERS, sid+`\`+windowsWinGetUserUninstallKey, 0, windowsWinGetUserMaxSubKeys, packageID); ok {
		return version, ""
	}
	return "", fmt.Sprintf("no per-user WinGet package %s in the user's registry (read while the user is signed in)", packageID)
}

// readWindowsWinGetPackageVersion returns the highest valid DisplayVersion
// among the subkeys of root\path named "<packageID>_<source>". limit bounds
// the subkeys listed (0: all, for an administrator-only key).
func readWindowsWinGetPackageVersion(root registry.Key, path string, access uint32, limit int, packageID string) (string, bool) {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|access)
	if err != nil {
		return "", false
	}
	defer key.Close()
	n := -1
	if limit > 0 {
		n = limit
	}
	names, err := key.ReadSubKeyNames(n)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false
	}
	prefix := strings.ToLower(packageID) + "_"
	best := ""
	for _, name := range names {
		if !strings.HasPrefix(strings.ToLower(name), prefix) {
			continue
		}
		sub, err := registry.OpenKey(root, path+`\`+name, registry.QUERY_VALUE|access)
		if err != nil {
			continue
		}
		version, _, err := sub.GetStringValue("DisplayVersion")
		_ = sub.Close()
		version = strings.TrimSpace(version)
		if err != nil || !isValidWindowsAgentVersion(version) {
			continue
		}
		if best == "" || compareWindowsEnterpriseVersion(version, best) > 0 {
			best = version
		}
	}
	return best, best != ""
}

// windowsStandaloneInstalledAgent returns where the profile has a CLI of
// connectorName installed that no version probe read, and what to do about
// it, or "" when it finds none. Only presence is checked, never through a
// junction: the install is then reported as unprotected instead of being a
// silent gap.
func windowsStandaloneInstalledAgent(profileHome, connectorName string) (string, string) {
	profileHome = strings.TrimSpace(profileHome)
	if !filepath.IsAbs(profileHome) {
		return "", ""
	}
	profileHome = filepath.Clean(profileHome)
	local := filepath.Join(profileHome, "AppData", "Local")
	npm := filepath.Join(profileHome, "AppData", "Roaming", "npm")
	links := filepath.Join(local, "Microsoft", "WinGet", "Links")
	var candidates []string
	switch connectorName {
	case "codex":
		candidates = []string{
			filepath.Join(windowsCodexStandaloneRoot(profileHome), "current"),
			windowsCodexStandaloneVisibleBin(profileHome),
			filepath.Join(npm, "codex.cmd"),
			filepath.Join(links, "codex.exe"),
		}
	case "copilot":
		candidates = []string{
			filepath.Join(npm, "copilot.cmd"),
			filepath.Join(links, "copilot.exe"),
		}
	default:
		return "", ""
	}
	for _, candidate := range candidates {
		if windowsInstallPathPresent(candidate) {
			return candidate, windowsStandaloneInstallFix(connectorName)
		}
	}
	packages := filepath.Join(local, "Microsoft", "WinGet", "Packages")
	if winpath.RejectReparseChain(packages) == nil {
		for _, packageID := range windowsWinGetPackageIDs[connectorName] {
			matches, _ := filepath.Glob(filepath.Join(packages, packageID+"_*"))
			if len(matches) != 0 {
				return matches[0], "its WinGet version is read from the user's registry while the user is signed in; the next enumeration after sign-in enrolls the account"
			}
		}
	}
	return "", ""
}

// windowsInstallPathPresent reports whether path exists below a plain folder
// chain; path itself may be a junction (install.ps1's), which is not
// followed.
func windowsInstallPathPresent(path string) bool {
	if winpath.RejectReparseChain(filepath.Dir(path)) != nil {
		return false
	}
	_, err := os.Lstat(path)
	return err == nil
}

// windowsStandaloneInstallFix is the operator-facing fix for an install whose
// version no probe can read.
func windowsStandaloneInstallFix(connectorName string) string {
	switch connectorName {
	case "codex":
		return "install it with npm install -g @openai/codex, install.ps1 (default location) or WinGet; the next enumeration enrolls the account"
	case "copilot":
		return "install it with npm install -g @github/copilot or WinGet; the next enumeration enrolls the account"
	default:
		return "install it in a location DefenseClaw reads; the next enumeration enrolls the account"
	}
}

// windowsCodexUnpublishedConsequence is the unprotected-agent consequence
// for Codex while the machine requirements.toml is not published.
const windowsCodexUnpublishedConsequence = "no user is enrolled for Codex, so Codex's machine requirements.toml is not published and it runs without DefenseClaw hooks"

// windowsCodexMachinePolicyPublished reports whether Codex's machine
// requirements.toml is in force. The guardian publishes it only while a user
// is enrolled for Codex; with none, nothing refuses an unregistered user. A
// path that cannot be resolved or inspected counts as published, as for
// Cursor. Replaced in tests.
var windowsCodexMachinePolicyPublished = func() bool {
	path, err := windowsCodexMachineRequirementsPath()
	if err != nil {
		return true
	}
	_, err = os.Lstat(path)
	return !errors.Is(err, os.ErrNotExist)
}
