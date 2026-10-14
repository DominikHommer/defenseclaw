// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// The guardian's target and protected-copy hash routes retain the shared
// digest's opened-file checks, including refusal of a link at either path.
func TestGuardianHookHashRoutesRejectLinkedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	body := []byte("hook release")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	for name, hash := range map[string]func(string) (string, error){
		"target": guardianTargetHookSHA256Hex,
		"copy":   guardianCopyHookSHA256Hex,
	} {
		if got, err := hash(path); err != nil || got != want {
			t.Fatalf("%s hash %q, err %v; want %q", name, got, err, want)
		}
		linked := path + ".link"
		if err := os.Symlink(path, linked); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		if got, err := hash(linked); err == nil {
			t.Errorf("%s accepted a linked file with hash %q", name, got)
		}
		if err := os.Remove(linked); err != nil {
			t.Fatal(err)
		}
	}
}
