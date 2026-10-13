// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestModelFileScanRootsCheckParentLinkBeforeProtectedFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks need privileges on Windows")
	}
	oldOS, oldFDA := discoveryGOOS, macOSFullDiskAccess
	t.Cleanup(func() { discoveryGOOS, macOSFullDiskAccess = oldOS, oldFDA })
	macOSFullDiskAccess = func() bool { return false }

	home := linkFreeTempDir(t)
	documents := filepath.Join(home, "Documents")
	protected := filepath.Join(documents, "app")
	plain := filepath.Join(home, "work", "app")
	writeModelTestFile(t, filepath.Join(protected, "private.gguf"), "gguf")
	writeModelTestFile(t, filepath.Join(plain, "plain.gguf"), "gguf")
	mustPackageScanLink(t, documents, filepath.Join(home, "code"))
	linked := filepath.Join(home, "code", "app")

	for _, tc := range []struct {
		name, goos, root string
		secureClient     bool
		wantRoots        int
		wantSkipped      bool
		wantDocuments    bool
		wantApp          bool
	}{
		{"parent link", "darwin", linked, false, 0, true, true, false},
		{"lexical protected root", "darwin", protected, false, 0, true, false, true},
		{"plain unprotected root", "darwin", plain, false, 1, false, false, false},
		{"Secure Client", "darwin", linked, true, 1, false, false, false},
		{"off macOS", "linux", linked, false, 1, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			discoveryGOOS = tc.goos
			svc := newModelFileTestService(t, home, tc.root, 100, false)
			svc.opts.SecureClient = tc.secureClient
			roots, rootErrors := svc.modelFileScanRootsWithErrors()
			if len(roots) != tc.wantRoots || len(rootErrors) != 0 {
				t.Fatalf("model roots = %+v, errors = %+v; want %d roots and no errors", roots, rootErrors, tc.wantRoots)
			}
			if len(roots) == 1 {
				want := tc.root
				if tc.root == linked {
					want = protected
				}
				if roots[0].path != want {
					t.Fatalf("model root path = %q, want %q", roots[0].path, want)
				}
			}
			if svc.tccSkipped != tc.wantSkipped ||
				svc.tccSkippedPaths[hashPath(documents)] != tc.wantDocuments ||
				svc.tccSkippedPaths[hashPath(protected)] != tc.wantApp {
				t.Fatalf("privacy skip = %t, Documents recorded = %t, app recorded = %t; want %t, %t, %t",
					svc.tccSkipped, svc.tccSkippedPaths[hashPath(documents)],
					svc.tccSkippedPaths[hashPath(protected)],
					tc.wantSkipped, tc.wantDocuments, tc.wantApp)
			}
		})
	}
}
