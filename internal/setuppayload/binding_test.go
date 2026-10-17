// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setuppayload

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPayloadBindingCoversFlavorAndEveryFile(t *testing.T) {
	files := map[string]string{
		"defenseclaw.exe":        strings.Repeat("ab", 32),
		"install-enterprise.ps1": strings.Repeat("CD", 32),
	}
	// The layout is a build-time contract with build-setup.sh: pin it.
	want := sha256.Sum256([]byte("defenseclaw-setup-payload-binding/v1\nflavor=standalone-unsigned\n" +
		strings.Repeat("ab", 32) + " defenseclaw.exe\n" +
		strings.Repeat("cd", 32) + " install-enterprise.ps1\n"))
	base := PayloadBinding("standalone-unsigned", files)
	if base != hex.EncodeToString(want[:]) {
		t.Fatalf("PayloadBinding = %s, want %x", base, want)
	}
	if PayloadBinding("standalone", files) == base {
		t.Fatal("the binding ignores the flavor")
	}
	changed := map[string]string{"defenseclaw.exe": strings.Repeat("ab", 31) + "ac", "install-enterprise.ps1": files["install-enterprise.ps1"]}
	if PayloadBinding("standalone-unsigned", changed) == base {
		t.Fatal("the binding ignores a file digest")
	}
	extra := map[string]string{"defenseclaw.exe": files["defenseclaw.exe"], "install-enterprise.ps1": files["install-enterprise.ps1"], "x.exe": strings.Repeat("00", 32)}
	if PayloadBinding("standalone-unsigned", extra) == base {
		t.Fatal("the binding ignores an added file")
	}
	renamed := map[string]string{"defenseclaw2.exe": files["defenseclaw.exe"], "install-enterprise.ps1": files["install-enterprise.ps1"]}
	if PayloadBinding("standalone-unsigned", renamed) == base {
		t.Fatal("the binding ignores a file name")
	}
}
