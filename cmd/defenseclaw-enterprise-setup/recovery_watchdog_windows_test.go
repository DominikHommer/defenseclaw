// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0726: the independent child waits until the uninstall parent has
// exited, then replays only a pending transaction. A successful uninstall
// leaves no pending record and must not be undone.
func TestStandaloneUninstallRecoveryWatcher(t *testing.T) {
	oldWait, oldPending, oldReplay := setupRecoveryWaitForParent, setupRecoveryPending, setupRecoveryReplay
	t.Cleanup(func() {
		setupRecoveryWaitForParent, setupRecoveryPending, setupRecoveryReplay = oldWait, oldPending, oldReplay
	})
	var events []string
	setupRecoveryWaitForParent = func(pid int) error { events = append(events, "parent exited"); return nil }
	setupRecoveryPending = func() (bool, error) { events = append(events, "pending checked"); return true, nil }
	setupRecoveryReplay = func() error { events = append(events, "replayed"); return nil }
	var output bytes.Buffer
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != 0 {
		t.Fatalf("pending uninstall recovery exit=%d: %s", code, output.String())
	}
	if want := []string{"parent exited", "pending checked", "replayed"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("recovery order=%v, want %v", events, want)
	}
	events = nil
	setupRecoveryPending = func() (bool, error) { events = append(events, "pending checked"); return false, nil }
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != 0 {
		t.Fatalf("committed uninstall recovery exit=%d: %s", code, output.String())
	}
	if want := []string{"parent exited", "pending checked"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("committed uninstall incorrectly replayed: %v", events)
	}
	events = nil
	setupRecoveryPending = func() (bool, error) { return true, nil }
	setupRecoveryReplay = func() error { return errors.New("recovery failed") }
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != enterpriseFailureExitCode {
		t.Fatalf("failed recovery exit=%d, want %d", code, enterpriseFailureExitCode)
	}
}

func TestStandaloneUninstallRecoveryRequiresRunningEnforcement(t *testing.T) {
	result := enterprisestatus.New("recover", "standalone", "windows", "1.0.4")
	result.OK = true
	result.Installed = true
	result.Services = []enterprisestatus.Service{
		{Kind: "gateway", State: "running", Required: true},
		{Kind: "guardian", State: "running", Required: true},
	}
	if err := proveStandaloneUninstallRecovery(*result); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*enterprisestatus.Result){
		func(r *enterprisestatus.Result) { r.TransactionPending = true },
		func(r *enterprisestatus.Result) { r.Installed = false },
		func(r *enterprisestatus.Result) { r.Services[0].State = "stopped" },
		func(r *enterprisestatus.Result) { r.Services[1].State = "stopped" },
	} {
		candidate := *result
		candidate.Services = append([]enterprisestatus.Service(nil), result.Services...)
		mutate(&candidate)
		if err := proveStandaloneUninstallRecovery(candidate); err == nil {
			t.Fatalf("unproven recovery accepted: %+v", candidate)
		}
	}
}
