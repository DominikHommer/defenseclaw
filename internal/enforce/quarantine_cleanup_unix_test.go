// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enforce

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// GAP-0502: failure after publication describes cleanup, not the location of
// every source file. Removing a directory can delete its contents before the
// parent directory's permissions prevent removal of the directory itself.
func TestQuarantineSourceCleanupFailureKeepsVerifiedCopy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires POSIX permissions as a non-root user")
	}
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			skills := filepath.Join(root, "skills")
			source := filepath.Join(skills, "review")
			if err := os.MkdirAll(skills, 0o700); err != nil {
				t.Fatal(err)
			}
			file := source
			if directory {
				if err := os.Mkdir(source, 0o700); err != nil {
					t.Fatal(err)
				}
				file = filepath.Join(source, "SKILL.md")
			}
			if err := os.WriteFile(file, []byte("benign review instructions\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			plan, err := NewAssetQuarantinePlan(filepath.Join(root, "quarantine"), []string{skills}, "skill", "review", "claudecode", source)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(skills, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(skills, 0o700); err != nil {
					t.Error(err)
				}
			})
			err = ExecuteAssetQuarantine(plan, "cleanup-failed")
			if !errors.Is(err, ErrQuarantinePublished) {
				t.Fatalf("cleanup failure = %v, want a published copy", err)
			}
			if err := requireAssetHash(plan.QuarantinePath, plan.ContentHash); err != nil {
				t.Fatalf("published copy lost or changed: %v", err)
			}
			if _, err := os.Lstat(source); err != nil {
				t.Fatalf("source entry should remain: %v", err)
			}
			if directory {
				if _, err := os.Lstat(file); !os.IsNotExist(err) {
					t.Fatalf("source contents should be removed before directory cleanup fails: %v", err)
				}
			} else if err := requireAssetHash(source, plan.ContentHash); err != nil {
				t.Fatalf("source file should remain unchanged: %v", err)
			}
		})
	}
}
