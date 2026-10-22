// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// ensureEnterpriseForeignHookRemovalFence prepares the stable lock inode
// before the guardian can publish a removal. The gateway gets read access
// through the same narrow ownership rule as the removal ledger. Reconcile
// never replaces this file, including on an upgrade.
func ensureEnterpriseForeignHookRemovalFence(dir string) error {
	for _, name := range []string{enterprisepolicy.ForeignHookRemovalsFenceFile, enterprisepolicy.ForeignHookCleanupFenceFile} {
		if err := ensureEnterpriseForeignHookFenceFile(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func ensureEnterpriseForeignHookFenceFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
		if createErr == nil {
			createErr = file.Close()
		}
		if createErr != nil && !errors.Is(createErr, os.ErrExist) {
			return fmt.Errorf("create foreign-hook removal fence: %w", createErr)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect foreign-hook removal fence: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		return fmt.Errorf("foreign-hook removal fence %s is not an empty regular file", path)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("protect foreign-hook removal fence: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return fmt.Errorf("own foreign-hook removal fence: %w", err)
	}
	return enterpriseHookAuthorizationFileTrustCheck(path)
}

// withEnterpriseForeignHookCleanupFence closes the read-to-remove interval.
// The gateway holds this lock until an allow has been sent, while the guardian
// holds it across cleanup and the removal-ledger commit. If it cannot be
// acquired, cleanup does not start and the existing foreign-hook guard stays.
// The fence belongs to the machine guardian, even when the cleanup target
// keeps its hook scripts in a different per-user data directory.
func withEnterpriseForeignHookCleanupFence(fn func() error) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return fn()
	}
	dataDir := cfg.DataDir
	if !filepath.IsAbs(dataDir) {
		return errors.New("foreign-hook cleanup data directory is unverified")
	}
	dir, err := prepareEnterpriseHookAuthorizationDir(dataDir)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, enterprisepolicy.ForeignHookCleanupFenceFile)
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	unlock, err := enterprisepolicy.LockForeignHookRemovals(ctx, path)
	if err != nil {
		return fmt.Errorf("foreign-hook cleanup fence unavailable: %w", err)
	}
	defer unlock()
	return fn()
}
