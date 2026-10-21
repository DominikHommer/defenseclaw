// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// Every inbox bundle ends in a receipt: the run applies the highest version
// and gives each lower one a failed(superseded) receipt.
func TestBundleInboxGivesLowerVersionsASupersededReceipt(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	for version, cfg := range map[uint64]string{2: v1 + "\n# two\n", 3: v2} {
		var buf bytes.Buffer
		if err := enterprisebundle.WriteArchive(&buf, b.signed(version, cfg)); err != nil {
			t.Fatal(err)
		}
		writeRooted(t, filepath.Join(b.env.bundleInboxDir(), fmt.Sprintf("v%d.dcbundle", version)), buf.String())
	}
	requireOK(t, b.run(Options{Action: ActionEnsure, BundleInbox: true}))
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(3) {
		t.Fatalf("state = %+v", st)
	}
	lower := b.receipt(bundleID(2))
	if lower.State != enterprisebundle.StateFailed || lower.ErrorCode != enterprisebundle.CodeSuperseded ||
		!strings.Contains(lower.ErrorMessage, "version 3") {
		t.Fatalf("lower inbox version receipt = %+v", lower)
	}
	if _, err := os.Lstat(filepath.Join(b.env.bundleStore().PublicReceiptEventsDir(), bundleID(2)+".json")); err != nil {
		t.Fatalf("no receipt event for the superseded bundle: %v", err)
	}
	last, _, err := b.env.bundleStore().Latest()
	if err != nil || last == nil || last.BundleID != bundleID(3) {
		t.Fatalf("latest = %+v, %v", last, err)
	}
}

// A damaged current version directory does not stop a changing run that
// gives no config: the installed config is kept, the run reports it, and a
// new bundle still applies. A --config is still refused.
func TestBundleDamagedCurrentVersionKeepsTheInstalledConfig(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	installed := b.read(b.env.Layout.ConfigPath)
	dir := b.env.bundleStore().VersionDir(b.state().Current.Dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, enterprisebundle.ConfigName)
	if err := os.Chmod(config, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("damaged: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := b.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if !hasWarning(r, codeBundleStateUnreadable) {
		t.Fatalf("warnings = %+v", r.Warnings)
	}
	if b.read(b.env.Layout.ConfigPath) != installed {
		t.Fatal("the run changed the installed config")
	}
	other := filepath.Join(t.TempDir(), "config.yaml")
	writeRooted(t, other, v2)
	requireError(t, b.run(Options{Action: ActionEnsure, ConfigFile: other}), codeBundleStateUnreadable)

	requireOK(t, b.apply(b.dir(2, v2)))
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(2) {
		t.Fatalf("state after a new bundle = %+v", st)
	}
}

// bundle_required says signed-bundle mode is on because a trust anchor file
// exists, without claiming who installed it.
func TestBundleRequiredNamesTheAnchorFileNotWhoInstalledIt(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	other := filepath.Join(t.TempDir(), "config.yaml")
	writeRooted(t, other, v2)
	r := b.run(Options{Action: ActionEnsure, ConfigFile: other})
	requireError(t, r, codeBundleRequired)
	for _, e := range r.Errors {
		if e.Code == codeBundleRequired && (strings.Contains(e.Message, "MDM") || !strings.Contains(e.Message, "a trust anchor file is installed at")) {
			t.Fatalf("bundle_required message = %q", e.Message)
		}
	}
}
