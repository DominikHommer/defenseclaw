// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// userOwnedSettingsReadPath resolves links chosen by the account that runs
// an OSS gateway. It checks both a link and its destination: following a
// different account's link could make Setup rewrite that account's file.
// Enterprise home confinement is checked by the caller before this function.
func userOwnedSettingsReadPath(path string) (string, error) {
	if runtime.GOOS == "windows" {
		return path, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	stop := filepath.Dir(filepath.Dir(abs))
	if home := filepath.Clean(userHomeDir()); managedPathWithin(abs, home) {
		stop = home
	}
	linked := false
	for current := abs; current != filepath.Dir(current); current = filepath.Dir(current) {
		if current == stop {
			break
		}
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("inspect settings path %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if err := validatePluginOwnerFromInfo(current, info); err != nil {
			return "", fmt.Errorf("another account owns settings link %s: %w", current, err)
		}
		target, err := filepath.EvalSymlinks(current)
		if err != nil {
			return "", fmt.Errorf("settings source is a link that cannot be followed: %w", err)
		}
		if err := validatePluginOwner(target); err != nil {
			return "", fmt.Errorf("another account owns settings link target %s: %w", target, err)
		}
		linked = true
	}
	if !linked {
		return path, nil
	}
	target, err := filepath.EvalSymlinks(abs)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil // a linked directory may hold no settings file yet
	}
	if err != nil {
		return "", fmt.Errorf("settings source is a link that cannot be followed: %w", err)
	}
	if err := validatePluginOwner(target); err != nil {
		return "", fmt.Errorf("another account owns settings link target %s: %w", target, err)
	}
	return target, nil
}
