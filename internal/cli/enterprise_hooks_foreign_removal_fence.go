// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// ensureEnterpriseForeignHookRemovalFence prepares the stable lock inode
// before the guardian can publish a removal. The gateway gets read access
// through the same narrow ownership rule as the removal ledger. Reconcile
// never replaces this file, including on an upgrade.
func ensureEnterpriseForeignHookRemovalFence(dir string) error {
	path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFenceFile)
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
