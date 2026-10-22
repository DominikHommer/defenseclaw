// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func writeEnterpriseHookProtectedFile(path string, data []byte) error {
	return safefile.Write(path, data)
}

// publishEnterpriseHookProtectedFile replaces a guardian record that the
// gateway reads without a lock: the staged file gets the record's mode and
// ownership and passes the trust check before the rename, so a reader finds
// either the old record or the new, trusted one, never one it cannot read.
func publishEnterpriseHookProtectedFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("protected machine file is not a regular non-link file: %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect protected machine file: %w", err)
	}
	parent := filepath.Dir(path)
	tmp, err := os.CreateTemp(parent, ".defenseclaw-machine-state-*")
	if err != nil {
		return fmt.Errorf("create protected machine file temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write protected machine file temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync protected machine file temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close protected machine file temp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		return fmt.Errorf("protect machine file temp: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(tmpPath); err != nil {
		return fmt.Errorf("own machine file temp: %w", err)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish protected machine file: %w", err)
	}
	if dir, err := os.Open(parent); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// writeEnterpriseHookAdminOnlyFile mirrors the Windows-only variant on non-
// Windows hosts. Off-Windows there is no AdminFile SDDL to enforce, so the
// implementation folds into safefile.Write like the protected-file variant.
func writeEnterpriseHookAdminOnlyFile(path string, data []byte) error {
	return safefile.Write(path, data)
}

// enterpriseHookGuardianRecordBusy is Windows-only: an atomic rename never
// leaves a guardian record unopenable here.
func enterpriseHookGuardianRecordBusy(error) bool { return false }
