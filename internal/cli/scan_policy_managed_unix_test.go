// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"strings"
	"testing"
)

// GAP-0052: on a managed Linux or macOS host `scan code` and `policy test`
// take the config-only start of the other administrator policy commands,
// so they never open the audit store the gateway service account owns. A
// standard account is refused there as by `policy validate`; the full
// start would have opened the store first.
func TestManagedScanCodeAndPolicyTestSkipTheAuditStore(t *testing.T) {
	withManagedRecord(t, "/opt/defenseclaw/bin/defenseclaw-gateway", true, nil)
	previousUID := managedHostCallerUID
	managedHostCallerUID = func() int { return 4242 }
	t.Cleanup(func() { managedHostCallerUID = previousUID })
	want := policyConfigOnlyPreRunE(policyValidateCmd, nil)
	if want == nil {
		t.Fatal("policy validate admitted a standard account on a managed host")
	}
	for name, run := range map[string]func() error{
		"scan code":   func() error { return scanCodeCmd.PersistentPreRunE(scanCodeCmd, nil) },
		"policy test": func() error { return policyTestCmd.PersistentPreRunE(policyTestCmd, nil) },
	} {
		if err := run(); err == nil || err.Error() != want.Error() {
			t.Fatalf("%s start = %v, want the config-only start (%v)", name, err, want)
		}
	}
	if policyTestCmd.PersistentPostRun == nil || !strings.Contains(scanCodeCmd.Use, "code") {
		t.Fatal("policy test lost its config-only post-run")
	}
}
