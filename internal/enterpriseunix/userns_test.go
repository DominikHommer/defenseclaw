// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A private mount namespace can hide every managed connector's policy from
// an agent. The Linux host setting must be applied before an agent can run,
// and status must stop reporting a complete deployment if it is loosened.
func TestLinuxManagedUserNamespacesAreDisabledAndDetected(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if got := h.read(sysctlMaxUserNamespaces); got != "0\n" {
		t.Fatalf("install left user namespaces enabled: %q", got)
	}
	if got := h.read(userNamespacesConfigPath); got != string(userNamespacesConfig) {
		t.Fatalf("install did not persist the restriction: %q", got)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if hasMessageCode(r.Errors, codeUserNamespaces) {
			t.Fatalf("%s rejects a restricted host: %+v", action, r.Errors)
		}
	}
	if err := os.WriteFile(h.env.P(sysctlMaxUserNamespaces), []byte("63229\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.OK || r.SecurityComplete || !hasMessageCode(r.Errors, codeUserNamespaces) {
			t.Fatalf("%s missed namespace bypass: ok=%v security_complete=%v errors=%+v", action, r.OK, r.SecurityComplete, r.Errors)
		}
	}
	repaired := h.run(Options{Action: ActionEnsure})
	if !repaired.Installed || repaired.SecurityComplete || !hasMessageCode(repaired.Errors, codeUserNamespaces) {
		t.Fatalf("ensure did not require a reboot after re-closing namespaces: %+v", repaired)
	}
	if got := h.read(sysctlMaxUserNamespaces); got != "0\n" {
		t.Fatalf("ensure did not restore user namespace restriction: %q", got)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		if result := h.run(Options{Action: action}); hasMessageCode(result.Errors, codeUserNamespaces) {
			t.Fatalf("%s still requires a reboot after boot ID changed: %+v", action, result.Errors)
		}
	}

	// A config-only check would miss a boot-time reopening of the bypass;
	// a live-only check would miss the next reboot's exposure.
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.OK || r.SecurityComplete || !hasMessageCode(r.Errors, codeUserNamespaces) {
			t.Fatalf("%s missed missing persistent restriction: %+v", action, r)
		}
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	if got := h.read(userNamespacesConfigPath); got != string(userNamespacesConfig) {
		t.Fatalf("ensure did not restore persistent restriction: %q", got)
	}
}

func TestLinuxUserNamespaceRestrictionUpgradesOlderDeployment(t *testing.T) {
	for _, version := range []string{"1.0.0", "1.0.1", "1.0.2", "1.0.3"} {
		t.Run(version, func(t *testing.T) {
			h := newTestHost(t, "linux")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload(version)}))
			record, err := h.env.loadDeployment()
			if err != nil {
				t.Fatal(err)
			}
			delete(record.Files, userNamespacesConfigPath)
			if err := h.env.saveDeployment(record); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(sysctlMaxUserNamespaces), []byte("63229\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if status := h.run(Options{Action: ActionStatus}); status.SecurityComplete || !hasMessageCode(status.Errors, codeUserNamespaces) {
				t.Fatalf("old record appeared protected before upgrade: %+v", status)
			}
			h.env.ProductVersion = "1.0.4"
			upgraded := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.4")})
			if !upgraded.Installed || upgraded.SecurityComplete || !hasMessageCode(upgraded.Errors, codeUserNamespaces) {
				t.Fatalf("upgrade did not require a reboot after re-closing namespaces: %+v", upgraded)
			}
			if got := h.read(sysctlMaxUserNamespaces); got != "0\n" {
				t.Fatalf("upgrade left user namespaces enabled: %q", got)
			}
			if got := h.read(userNamespacesConfigPath); got != string(userNamespacesConfig) {
				t.Fatalf("upgrade did not install persistent restriction: %q", got)
			}
			record, err = h.env.loadDeployment()
			if err != nil || record.Files[userNamespacesConfigPath] == "" {
				t.Fatalf("upgrade did not track persistent restriction: record=%+v err=%v", record, err)
			}
			if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if status := h.run(Options{Action: ActionStatus}); hasMessageCode(status.Errors, codeUserNamespaces) {
				t.Fatalf("upgrade remained incomplete after reboot: %+v", status.Errors)
			}
		})
	}
}

func TestLinuxFreshInstallFromUnrestrictedHostRequiresReboot(t *testing.T) {
	h := newTestHost(t, "linux")
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.env.P(userNamespaceBootMarker)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(sysctlMaxUserNamespaces), []byte("63229\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	installed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	if !installed.Installed || installed.SecurityComplete || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("fresh install marked the current boot complete: %+v", installed)
	}
	if h.read(sysctlMaxUserNamespaces) != "0\n" || h.read(userNamespacesConfigPath) != string(userNamespacesConfig) {
		t.Fatal("fresh install did not enforce and persist the restriction")
	}
	if status := h.run(Options{Action: ActionStatus}); status.SecurityComplete || !hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status marked the old boot complete: %+v", status)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if status := h.run(Options{Action: ActionStatus}); status.SecurityComplete || !hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status trusted an empty reboot marker: %+v", status)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootMarker), []byte("boot-before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if status := h.run(Options{Action: ActionStatus}); hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status did not clear the reboot requirement: %+v", status.Errors)
	}
}

func TestLinuxFreshInstallWithZeroSettingStillRequiresReboot(t *testing.T) {
	h := newTestHost(t, "linux")
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.env.P(userNamespaceBootMarker)); err != nil {
		t.Fatal(err)
	}
	installed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	if !installed.Installed || installed.SecurityComplete || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("fresh install trusted a zero setting without proof of a reboot: %+v", installed)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-before\n" {
		t.Fatalf("fresh install did not record the boot needing a reboot: %q", marker)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if status := h.run(Options{Action: ActionStatus}); hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status did not accept the rebooted, restricted host: %+v", status.Errors)
	}
	if err := os.Remove(h.env.P(userNamespaceBootMarker)); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		if result := h.run(Options{Action: action}); result.SecurityComplete || !hasMessageCode(result.Errors, codeUserNamespaces) {
			t.Fatalf("%s accepted a missing reboot attestation: %+v", action, result)
		}
	}
	repaired := h.run(Options{Action: ActionEnsure})
	if !repaired.Installed || repaired.SecurityComplete || !hasMessageCode(repaired.Errors, codeUserNamespaces) {
		t.Fatalf("ensure did not recreate a missing marker and require reboot: %+v", repaired)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-after\n" {
		t.Fatalf("ensure did not mark the current boot: %q", marker)
	}
}

func TestLinuxPackageInstallEnforcesUserNamespaceRestriction(t *testing.T) {
	h := packageHost(t, "1.0.0")
	if err := os.WriteFile(h.env.P(sysctlMaxUserNamespaces), []byte("63229\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	installed := h.run(Options{Action: ActionInstall, FromPackage: true, Reason: "package"})
	if !installed.Installed || installed.SecurityComplete || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("package install did not close namespaces and require a reboot: %+v", installed)
	}
	if h.read(sysctlMaxUserNamespaces) != "0\n" || h.read(userNamespacesConfigPath) != string(userNamespacesConfig) {
		t.Fatal("package install did not enforce and persist the host restriction")
	}
	record, err := h.env.loadDeployment()
	if err != nil || record.Files[userNamespacesConfigPath] == "" {
		t.Fatalf("package install did not track the host restriction: record=%+v err=%v", record, err)
	}
	raw, err := json.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.env.P(h.env.Layout.LifecycleDir), lastPackageResultFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if failure := h.env.lastPackageInstallFailure(); failure != "" {
		t.Fatalf("committed package waiting for reboot reported an unapplied package: %q", failure)
	}
	if status := h.run(Options{Action: ActionStatus}); hasMessageCode(status.Warnings, codePackageInstallFailed) || !hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status confused reboot requirement with an unapplied package: %+v", status)
	}
}

func TestLinuxNamespaceRebootMarkerSurvivesUninstall(t *testing.T) {
	h := newTestHost(t, "linux")
	if err := os.WriteFile(h.env.P(sysctlMaxUserNamespaces), []byte("63229\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	installed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	if !installed.Installed || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("first install did not mark the boot incomplete: %+v", installed)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-before\n" {
		t.Fatalf("wrong reboot marker: %q", marker)
	}
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	if marker := h.read(userNamespaceBootMarker); marker != "boot-before\n" {
		t.Fatalf("uninstall removed the reboot marker: %q", marker)
	}
	if got := h.read(sysctlMaxUserNamespaces); got != "0\n" {
		t.Fatalf("uninstall reopened user namespaces: %q", got)
	}
	reinstalled := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	if !reinstalled.Installed || reinstalled.SecurityComplete || !hasMessageCode(reinstalled.Errors, codeUserNamespaces) {
		t.Fatalf("reinstall in the same boot forgot prior namespaces: %+v", reinstalled)
	}
}

func TestLinuxSafeSameBootReinstallAndUnrestrictedReboot(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	if marker := h.read(userNamespaceUninstalled); marker != "boot-before\n" {
		t.Fatalf("uninstall did not record when the persistent restriction was removed: %q", marker)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	// The fake kernel stays at zero, but the managed sysctl file was absent
	// across this reboot. The old boot marker no longer proves safety.
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reinstalled := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	if !reinstalled.Installed || reinstalled.SecurityComplete || !hasMessageCode(reinstalled.Errors, codeUserNamespaces) {
		t.Fatalf("reinstall trusted a boot without the persistent restriction: %+v", reinstalled)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-after\n" {
		t.Fatalf("reinstall did not require a new reboot: %q", marker)
	}
}

func TestLinuxReinstallAfterUnprovenUninstallRequiresReboot(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	if marker := h.read(userNamespaceUninstalled); marker != "unproven:boot-before\n" {
		t.Fatalf("uninstall trusted a missing host restriction: %q", marker)
	}
	reinstalled := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	if !reinstalled.Installed || reinstalled.SecurityComplete || !hasMessageCode(reinstalled.Errors, codeUserNamespaces) {
		t.Fatalf("reinstall trusted an unproven boot: %+v", reinstalled)
	}
}

func TestLinuxUserNamespaceRestrictionFailsWithoutKernelSetting(t *testing.T) {
	h := newTestHost(t, "linux")
	if err := os.Remove(h.env.P(sysctlMaxUserNamespaces)); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	if r.OK || !hasMessageCode(r.Errors, codeUserNamespaces) {
		t.Fatalf("install claimed protection without a kernel setting: %+v", r)
	}
	if _, err := os.Stat(h.env.P(sysctlMaxUserNamespaces)); !os.IsNotExist(err) {
		t.Fatalf("install invented a missing kernel setting: %v", err)
	}
}

func TestLinuxUserNamespaceRestrictionRefusesUntrustedConfigDirectory(t *testing.T) {
	h := newTestHost(t, "linux")
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	h.env.Trust = func(_ string, kind TrustKind) error {
		if kind == TrustAdminDir {
			return errors.New("standard user can replace the directory")
		}
		return nil
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	if r.OK || !hasMessageCode(r.Errors, codeApply) {
		t.Fatalf("install wrote a host setting through an untrusted directory: %+v", r)
	}
	if _, err := os.Stat(h.env.P(userNamespacesConfigPath)); !os.IsNotExist(err) {
		t.Fatalf("install left a host setting under an untrusted directory: %v", err)
	}
}

func TestMacOSUserNamespaceSettingIsNotRequired(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
	h.env.ProductVersion = "1.0.4"
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.4")}))
	if problem := h.env.userNamespaceProblem(); problem != "" {
		t.Fatal(problem)
	}
	if err := h.env.disableUnprivilegedUserNamespaces(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.env.P(userNamespacesConfigPath)); !os.IsNotExist(err) {
		t.Fatalf("macOS install wrote a Linux sysctl file: %v", err)
	}
}
