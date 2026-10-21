// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// Bundle verify and apply read credential presence through
// Env.SecretPresent: a file the `secret status` listing names is present
// only when the gateway could use it, so a required reference to an empty
// or otherwise unusable file refuses secret_ref_missing on both. A file the
// host trust check refuses is missing too.
func TestSecretPresentClassifiesUsabilityLikeTheGateway(t *testing.T) {
	h := newTestHost(t, "linux")
	dir := h.env.P(h.env.Layout.SecretsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	untrusted := filepath.Join(dir, "untrusted-key")
	h.env.Trust = func(path string, kind TrustKind) error {
		if path == untrusted && kind == TrustAdminFile {
			return errors.New("not administrator-owned")
		}
		return nil
	}
	for name, body := range map[string]string{
		"ai-defense-api-key": "key-1\n", "empty-key": "", "multi-line": "a\nb\n", "untrusted-key": "key-2",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names, _, err := h.env.listSecrets()
	if err != nil || len(names) != 4 {
		t.Fatalf("secret status lists %v (%v), want every stored file", names, err)
	}
	for name, want := range map[string]bool{
		"ai-defense-api-key": true, "empty-key": false, "multi-line": false, "untrusted-key": false, "not-stored": false,
	} {
		if present, err := h.env.SecretPresent(name); err != nil || present != want {
			t.Errorf("%s: present %v, err %v; want %v", name, present, err, want)
		}
	}
}

// A required credential whose check fails (here the trust check cannot read
// the file's metadata) refuses the apply with secret_ref_missing: the apply
// never passes the credential gate on a lookup it could not finish.
func TestBundleApplyRefusesARequiredCredentialItCannotCheck(t *testing.T) {
	b := newBundleHost(t)
	v1, _, _ := bundleConfigs(b.testHost)
	cfg := strings.Replace(v1, "  profile: standalone\n",
		"  profile: standalone\n  inspection:\n    ai_defense:\n      credential: ai-defense-api-key\n", 1)
	if cfg == v1 {
		t.Fatal("the default config has no enterprise profile line to extend")
	}
	if err := b.env.WriteSecret(context.Background(), "ai-defense-api-key", []byte("key-1")); err != nil {
		t.Fatal(err)
	}
	secret := b.env.P(filepath.Join(b.env.Layout.SecretsDir, "ai-defense-api-key"))
	trust := b.env.Trust
	b.env.Trust = func(path string, kind TrustKind) error {
		if path == secret {
			return &os.PathError{Op: "stat", Path: path, Err: syscall.EIO}
		}
		return trust(path, kind)
	}
	if _, err := b.env.SecretPresent("ai-defense-api-key"); err == nil {
		t.Fatal("presence of a credential whose metadata cannot be read: no error")
	}
	b.mapPromotedBundleOwners(1)
	r := b.apply(b.dir(1, cfg))
	requireError(t, r, string(enterprisebundle.CodeSecretRefMissing))
	if st := b.state(); st.Current != nil {
		t.Fatalf("refused apply confirmed %+v", st.Current)
	}
}
