//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A configured machine-policy connector stays active with no enrolled SIDs.
// The same state occurs on a fresh install and after the final account is cut
// off; the guardian must publish an empty registry, not remove its hook.
func TestWindowsConfiguredMachinePolicySurvivesEmptyEnrollment(t *testing.T) {
	for _, name := range []string{"claudecode", "codex", "cursor"} {
		t.Run(name, func(t *testing.T) {
			previousCfg := cfg
			previousClaudeReader, previousClaudePublisher := enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher
			previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
			previousCodexRemover, previousCodexPublisher := enterpriseHookCodexRequirementsRemover, enterpriseHookCodexTargetsPublisher
			previousCursorReader, previousCursorPublisher := enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher
			previousClaudeDeactivator, previousCursorDeactivator := enterpriseHookClaudePolicyDeactivator, enterpriseHookCursorPolicyDeactivator
			previousClaudeIdentity, previousCursorIdentity := enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier
			t.Cleanup(func() {
				cfg = previousCfg
				enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher = previousClaudeReader, previousClaudePublisher
				enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
				enterpriseHookCodexRequirementsRemover, enterpriseHookCodexTargetsPublisher = previousCodexRemover, previousCodexPublisher
				enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher = previousCursorReader, previousCursorPublisher
				enterpriseHookClaudePolicyDeactivator, enterpriseHookCursorPolicyDeactivator = previousClaudeDeactivator, previousCursorDeactivator
				enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier = previousClaudeIdentity, previousCursorIdentity
			})
			cfg = &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
				Guardrail:      config.GuardrailConfig{Connector: name},
			}
			active := true
			enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) { return nil, name == "claudecode" && active, nil }
			enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
				return nil, name == "cursor" && active, nil
			}
			enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
				return connector.WindowsCodexMachineRequirementsOptions{HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
			}
			enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
				return connector.WindowsCodexManagedRuntimeRegistry{Active: name == "codex" && active, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
			}
			var removedCodex bool
			var removedOther bool
			enterpriseHookClaudePolicyDeactivator = func() error { removedOther, active = true, false; return nil }
			enterpriseHookCursorPolicyDeactivator = func() error { removedOther, active = true, false; return nil }
			enterpriseHookCodexRequirementsRemover = func(connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
				removedCodex = true
				active = false
				return connector.WindowsCodexMachineRequirementsReport{OK: true, SafeToRemoveBinary: true}, nil
			}
			enterpriseHookClaudePolicyTargetsPublisher = func([]string) error { return nil }
			enterpriseHookCursorPolicyTargetsPublisher = func([]enterprisehooks.WindowsCursorManagedRuntimeTarget) error { return nil }
			enterpriseHookCodexTargetsPublisher = func(connector.WindowsCodexMachineRequirementsOptions, []connector.WindowsCodexManagedRuntimeTarget) error {
				return nil
			}
			enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
			enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }

			manifest := enterprisehooks.Manifest{}
			if err := syncEnterpriseHookManagedMachineEnrollments(manifest, "127.0.0.1:32109", false); err != nil {
				t.Fatal(err)
			}
			if removedCodex {
				t.Fatal("empty Codex enrollment removed configured machine requirements")
			}
			if err := verifyEnterpriseHookManagedEnrollments(manifest, "127.0.0.1:32109"); err != nil {
				t.Fatalf("configured %s policy with zero targets failed verify: %v", name, err)
			}
			cfg.Guardrail.Connector = "copilot"
			if err := syncEnterpriseHookManagedMachineEnrollments(manifest, "127.0.0.1:32109", true); err != nil {
				t.Fatal(err)
			}
			if active || (!removedCodex && !removedOther) {
				t.Fatal("removing the connector from admin config did not remove its machine hook")
			}
			if err := verifyEnterpriseHookManagedEnrollments(manifest, "127.0.0.1:32109"); err != nil {
				t.Fatalf("removed %s policy failed verify: %v", name, err)
			}
		})
	}
}

// Upgrading an older standalone install can start with no machine policy at
// all for a configured connector. Reconcile must restore its guard before it
// publishes the still-empty enrollment registry.
func TestWindowsConfiguredMachinePolicyRepairsLegacyEmptyEnrollment(t *testing.T) {
	for _, name := range []string{"claudecode", "codex", "cursor"} {
		t.Run(name, func(t *testing.T) {
			previousCfg := cfg
			previousClaudeReader, previousClaudePublisher := enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher
			previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
			previousCodexReconciler, previousCodexPublisher := enterpriseHookCodexRequirementsReconciler, enterpriseHookCodexTargetsPublisher
			previousCursorReader, previousCursorPublisher := enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher
			previousClaudeEnsurer, previousCursorEnsurer := enterpriseHookClaudePolicyEnsurer, enterpriseHookCursorPolicyEnsurer
			previousClaudeIdentity, previousCursorIdentity := enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier
			t.Cleanup(func() {
				cfg = previousCfg
				enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher = previousClaudeReader, previousClaudePublisher
				enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
				enterpriseHookCodexRequirementsReconciler, enterpriseHookCodexTargetsPublisher = previousCodexReconciler, previousCodexPublisher
				enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher = previousCursorReader, previousCursorPublisher
				enterpriseHookClaudePolicyEnsurer, enterpriseHookCursorPolicyEnsurer = previousClaudeEnsurer, previousCursorEnsurer
				enterpriseHookClaudePolicyIdentityVerifier, enterpriseHookCursorPolicyIdentityVerifier = previousClaudeIdentity, previousCursorIdentity
			})
			cfg = &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
				Guardrail:      config.GuardrailConfig{Connector: name},
			}
			active := false
			ensured := false
			enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) { return nil, name == "claudecode" && active, nil }
			enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
				return nil, name == "cursor" && active, nil
			}
			enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
				return connector.WindowsCodexMachineRequirementsOptions{HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
			}
			enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
				return connector.WindowsCodexManagedRuntimeRegistry{Active: name == "codex" && active, GatewayAddr: "127.0.0.1:32109", GatewayServiceName: "DefenseClawGateway"}, nil
			}
			enterpriseHookClaudePolicyEnsurer = func(connector.SetupOpts) error { active, ensured = true, true; return nil }
			enterpriseHookCursorPolicyEnsurer = func(connector.SetupOpts) error { active, ensured = true, true; return nil }
			enterpriseHookCodexRequirementsReconciler = func(opts connector.WindowsCodexMachineRequirementsOptions) (connector.WindowsCodexMachineRequirementsReport, error) {
				if !opts.CodexTargetEnabled {
					t.Fatal("Codex repair did not enable the configured machine guard")
				}
				active, ensured = true, true
				return connector.WindowsCodexMachineRequirementsReport{OK: true}, nil
			}
			enterpriseHookClaudePolicyTargetsPublisher = func([]string) error { return nil }
			enterpriseHookCursorPolicyTargetsPublisher = func([]enterprisehooks.WindowsCursorManagedRuntimeTarget) error { return nil }
			enterpriseHookCodexTargetsPublisher = func(connector.WindowsCodexMachineRequirementsOptions, []connector.WindowsCodexManagedRuntimeTarget) error {
				return nil
			}
			enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
			enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }
			manifest := enterprisehooks.Manifest{}
			if err := syncEnterpriseHookManagedMachineEnrollments(manifest, "127.0.0.1:32109", true); err != nil {
				t.Fatal(err)
			}
			if !ensured || !active {
				t.Fatal("legacy empty enrollment did not restore the configured machine guard")
			}
			if err := verifyEnterpriseHookManagedEnrollments(manifest, "127.0.0.1:32109"); err != nil {
				t.Fatalf("restored empty policy failed verify: %v", err)
			}
		})
	}
}

func TestWindowsClaudeDeletedPolicyReconcileRetainsEnrolledTargets(t *testing.T) {
	const aliceSID = "S-1-12-1-1111111111-2222222222-3333333333-4000000000"
	previousCfg := cfg
	previousClaudeReader, previousClaudePublisher := enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher
	previousClaudeEnsurer := enterpriseHookClaudePolicyEnsurer
	previousCodexLayout, previousCodexReader := enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader
	previousCursorReader, previousCursorPublisher := enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookClaudePolicyTargetsReader, enterpriseHookClaudePolicyTargetsPublisher = previousClaudeReader, previousClaudePublisher
		enterpriseHookClaudePolicyEnsurer = previousClaudeEnsurer
		enterpriseHookCodexRequirementsLayoutResolver, enterpriseHookCodexRuntimeRegistryReader = previousCodexLayout, previousCodexReader
		enterpriseHookCursorPolicyTargetsReader, enterpriseHookCursorPolicyTargetsPublisher = previousCursorReader, previousCursorPublisher
	})
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		Guardrail:      config.GuardrailConfig{Connector: "claudecode"},
	}
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{
		SID: aliceSID, UserHome: `C:\Users\alice`, Connector: "claudecode",
	}}}
	policyPresent := false
	ensures := 0
	published := 0
	enterpriseHookClaudePolicyTargetsReader = func() ([]string, bool, error) {
		if !policyPresent {
			return nil, false, errors.New("ownership metadata is incomplete")
		}
		return []string{aliceSID}, true, nil
	}
	enterpriseHookClaudePolicyEnsurer = func(opts connector.SetupOpts) error {
		if opts.ManagedTargetSID != "" {
			t.Fatalf("machine-policy repair enrolled a new SID: %s", opts.ManagedTargetSID)
		}
		ensures++
		policyPresent = true
		return nil
	}
	enterpriseHookClaudePolicyTargetsPublisher = func(targets []string) error {
		published++
		if len(targets) != 1 || targets[0] != aliceSID {
			t.Fatalf("reconcile published %v, want Alice retained", targets)
		}
		return nil
	}
	enterpriseHookCodexRequirementsLayoutResolver = func(string) (connector.WindowsCodexMachineRequirementsOptions, error) {
		return connector.WindowsCodexMachineRequirementsOptions{
			HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		}, nil
	}
	enterpriseHookCodexRuntimeRegistryReader = func(string) (connector.WindowsCodexManagedRuntimeRegistry, error) {
		return connector.WindowsCodexManagedRuntimeRegistry{}, nil
	}
	enterpriseHookCursorPolicyTargetsReader = func() ([]enterprisehooks.WindowsCursorManagedRuntimeTarget, bool, error) {
		return nil, false, nil
	}
	enterpriseHookCursorPolicyTargetsPublisher = func([]enterprisehooks.WindowsCursorManagedRuntimeTarget) error { return nil }
	for _, publishExact := range []bool{false, true} {
		if err := syncEnterpriseHookManagedMachineEnrollments(manifest, "127.0.0.1:32109", publishExact); err != nil {
			t.Fatalf("reconcile publication (exact=%t): %v", publishExact, err)
		}
	}
	if ensures != 1 || published != 2 {
		t.Fatalf("reconcile ensured policy %d times and published targets %d times", ensures, published)
	}
}

func TestDeferredTargetSessionAvailabilityDowngradesOnlyTypedAbsence(t *testing.T) {
	previous := enterpriseHookWindowsTargetSessionCheck
	previousPending := enterpriseHookWindowsDeferredPendingCheck
	t.Cleanup(func() {
		enterpriseHookWindowsTargetSessionCheck = previous
		enterpriseHookWindowsDeferredPendingCheck = previousPending
	})
	target := enterprisehooks.ManifestTarget{
		SID:      "S-1-5-21-1-2-3-1001",
		UserHome: `C:\Users\alice`,
	}
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error {
		return nil
	}

	enterpriseHookWindowsTargetSessionCheck = func(string, string) error {
		return &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	}
	available, err := enterpriseHookDeferredTargetSessionAvailable(target)
	if err != nil || available {
		t.Fatalf("typed absence = available %t err %v, want false/nil", available, err)
	}

	sentinel := errors.New("WTS token query denied")
	enterpriseHookWindowsTargetSessionCheck = func(string, string) error {
		return sentinel
	}
	available, err = enterpriseHookDeferredTargetSessionAvailable(target)
	if available || !errors.Is(err, sentinel) {
		t.Fatalf("ordinary WTS failure = available %t err %v, want hard error", available, err)
	}

	enterpriseHookWindowsTargetSessionCheck = func(string, string) error {
		return &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	}
	selectorErr := errors.New("selected runtime lacks protected authorization")
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error {
		return selectorErr
	}
	available, err = enterpriseHookDeferredTargetSessionAvailable(target)
	if available || !errors.Is(err, selectorErr) {
		t.Fatalf("stale runtime = available %t err %v, want hard error", available, err)
	}

	available, err = enterpriseHookTargetSessionAvailable(target)
	if err != nil || available {
		t.Fatalf("protected-runtime session absence = available %t err %v, want false/nil", available, err)
	}
}

func TestDeferredPendingRaceRechecksSessionAndSelectorState(t *testing.T) {
	previousSession := enterpriseHookWindowsTargetSessionCheck
	previousPending := enterpriseHookWindowsDeferredPendingCheck
	t.Cleanup(func() {
		enterpriseHookWindowsTargetSessionCheck = previousSession
		enterpriseHookWindowsDeferredPendingCheck = previousPending
	})
	target := enterprisehooks.ManifestTarget{
		SID:       "S-1-5-21-1-2-3-1001",
		UserHome:  `C:\Users\alice`,
		Connector: "codex",
		Deferred:  true,
	}
	original := &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	enterpriseHookWindowsTargetSessionCheck = func(string, string) error { return original }
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error { return nil }

	pending, err := enterpriseHookDeferredPendingAfterSessionError(target, false, original)
	if err != nil || !pending {
		t.Fatalf("stable absence = pending %t err %v, want true/nil", pending, err)
	}

	enterpriseHookWindowsTargetSessionCheck = func(string, string) error { return nil }
	pending, err = enterpriseHookDeferredPendingAfterSessionError(target, false, original)
	if pending || !errors.Is(err, original) {
		t.Fatalf("session reappeared = pending %t err %v, want original hard error", pending, err)
	}
}

func TestExpandEnterpriseHookProfileImagePathUsesTrustedSystemDrive(t *testing.T) {
	previous := enterpriseHookWindowsSystemDirectory
	t.Cleanup(func() { enterpriseHookWindowsSystemDirectory = previous })
	enterpriseHookWindowsSystemDirectory = func() (string, error) {
		return `D:\Windows\System32`, nil
	}
	t.Setenv("SystemDrive", `Z:`)

	got, err := expandEnterpriseHookProfileImagePath(`%SystemDrive%\Users\managed`)
	if err != nil {
		t.Fatalf("expand ProfileImagePath: %v", err)
	}
	want := filepath.Clean(`D:\Users\managed`)
	if filepath.Clean(got) != want {
		t.Fatalf("expanded ProfileImagePath = %q, want %q", got, want)
	}
}

func TestExpandEnterpriseHookProfileImagePathRejectsOtherVariables(t *testing.T) {
	if _, err := expandEnterpriseHookProfileImagePath(`%USERPROFILE%\managed`); err == nil {
		t.Fatal("ProfileImagePath with user-controlled expansion was accepted")
	}
}

func TestWindowsEnterpriseDesiredEnrollmentsResolvesLocalUser(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("resolve current user: %v", err)
	}
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{
		User:      current.Username,
		Connector: "codex",
	}}}

	_, codex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		t.Fatalf("resolve desired enrollments: %v", err)
	}
	if len(codex) != 1 {
		t.Fatalf("Codex enrollment count = %d, want 1", len(codex))
	}
	if !strings.EqualFold(codex[0].SID, current.Uid) {
		t.Fatalf("Codex enrollment SID = %q, want %q", codex[0].SID, current.Uid)
	}
	wantDataDir := filepath.Join(filepath.Clean(current.HomeDir), ".defenseclaw")
	if !sameWindowsEnterprisePathCLI(codex[0].DataDir, wantDataDir) {
		t.Fatalf("Codex enrollment data dir = %q, want %q", codex[0].DataDir, wantDataDir)
	}
}

func TestWindowsEnterpriseDesiredEnrollmentsAcceptEntraIDForAllConnectors(t *testing.T) {
	const entraSID = "S-1-12-1-1111111111-2222222222-3333333333-4000000000"
	home := filepath.Clean(`C:\Users\entra-user`)
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{
		{SID: entraSID, UserHome: home, Connector: "claudecode"},
		{SID: entraSID, UserHome: home, Connector: "codex"},
		{SID: entraSID, UserHome: home, Connector: "cursor"},
	}}

	claude, codex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		t.Fatalf("resolve Claude Code and Codex enrollments: %v", err)
	}
	if len(claude) != 1 || claude[0] != entraSID {
		t.Fatalf("Claude Code enrollments = %v, want %s", claude, entraSID)
	}
	if len(codex) != 1 || codex[0].SID != entraSID ||
		!sameWindowsEnterprisePathCLI(codex[0].DataDir, filepath.Join(home, ".defenseclaw")) {
		t.Fatalf("Codex enrollments = %+v, want Microsoft Entra ID target", codex)
	}
	cursor, err := windowsEnterpriseDesiredCursorEnrollments(manifest)
	if err != nil {
		t.Fatalf("resolve Cursor enrollments: %v", err)
	}
	if len(cursor) != 1 || cursor[0].SID != entraSID ||
		!sameWindowsEnterprisePathCLI(cursor[0].DataDir, filepath.Join(home, ".defenseclaw")) {
		t.Fatalf("Cursor enrollments = %+v, want Microsoft Entra ID target", cursor)
	}
}

func TestManagedEnrollmentIdentityRejectsStaleDeploymentWithSameSID(t *testing.T) {
	previousClaude := enterpriseHookClaudePolicyIdentityVerifier
	previousCursor := enterpriseHookCursorPolicyIdentityVerifier
	t.Cleanup(func() {
		enterpriseHookClaudePolicyIdentityVerifier = previousClaude
		enterpriseHookCursorPolicyIdentityVerifier = previousCursor
	})
	opts := connector.WindowsCodexMachineRequirementsOptions{
		HookBinary:         `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:32109",
		GatewayServiceName: "DefenseClawGateway",
	}
	current := connector.WindowsCodexManagedRuntimeRegistry{
		Active:             true,
		GatewayAddr:        opts.GatewayAddr,
		GatewayServiceName: opts.GatewayServiceName,
		Targets: []connector.WindowsCodexManagedRuntimeTarget{{
			SID:     "S-1-5-21-1-2-3-1001",
			DataDir: `C:\Users\alice\.defenseclaw`,
		}},
	}
	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); err != nil {
		t.Fatalf("exact identity: %v", err)
	}

	staleClaude := errors.New("stale Claude gateway identity")
	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return staleClaude }
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); !errors.Is(err, staleClaude) {
		t.Fatalf("stale Claude identity error = %v, want %v", err, staleClaude)
	}

	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
	staleCursor := errors.New("stale Cursor gateway identity")
	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return staleCursor }
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); !errors.Is(err, staleCursor) {
		t.Fatalf("stale Cursor identity error = %v, want %v", err, staleCursor)
	}

	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }
	current.GatewayServiceName = "DefenseClawGateway_Old"
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); err == nil {
		t.Fatal("stale Codex gateway identity was accepted because the SID set matched")
	}
}
