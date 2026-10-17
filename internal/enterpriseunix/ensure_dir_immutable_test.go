// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"testing"
)

func TestR103B07EnsureDirSkipsUnchangedOwner(t *testing.T) {
	dir := t.TempDir()
	owner := fileOwner{UID: 17, GID: 23}
	env := &Env{
		OwnerOf: func(string) (int, int, error) { return owner.UID, owner.GID, nil },
		Lchown:  func(string, int, int) error { return errors.New("immutable directory refuses chown") },
	}
	if err := env.ensureDir(dir, 0700, owner); err != nil {
		t.Fatalf("already correct directory metadata failed: %v", err)
	}
}

func TestR103B07EnsureDirStillRepairsChangedMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	env := &Env{
		OwnerOf: func(string) (int, int, error) { return 17, 23, nil },
		Lchown:  func(string, int, int) error { return errors.New("unexpected chown") },
	}
	if err := env.ensureDir(dir, 0700, fileOwner{UID: 17, GID: 23}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("mode=%v, err=%v; want 0700", info, err)
	}
}
