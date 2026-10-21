// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// codeProductFloor refuses a downgrade below the release the confirmed
// signed policy bundle requires (its min_product_version).
const codeProductFloor = "product_floor_refused"

// confirmedBundleProductFloor reads the confirmed bundle's release floor
// (tests replace it).
var confirmedBundleProductFloor = func(s *enterprisebundle.Store) (string, error) { return s.ConfirmedProductFloor() }

// BundleProductFloorRefusal refuses installing DefenseClaw version on a
// device that takes signed bundles (its trust anchors are installed) when
// the confirmed bundle needs a later release, or when that floor cannot be
// read. The administrator's rollback marker and --allow-downgrade do not
// lift it: a bundle signed with a lower --min-product-version does.
func (e *Env) BundleProductFloorRefusal(version string) error {
	if _, err := os.Lstat(e.bundleAnchorsPath()); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return &codedError{code: codeProductFloor, err: fmt.Errorf("cannot check the bundle trust anchors, so the release floor of the confirmed policy bundle is unknown: %w", err)}
	}
	floor, err := confirmedBundleProductFloor(e.bundleStore())
	if err != nil {
		return &codedError{code: codeProductFloor, err: fmt.Errorf("cannot read the release floor of the confirmed policy bundle: %w", err)}
	}
	if floor != "" && compareProductVersions(version, floor) < 0 {
		return &codedError{code: codeProductFloor, err: fmt.Errorf("the confirmed signed policy bundle needs DefenseClaw %s or later, and this is %s; to go back, deliver a bundle signed with a lower --min-product-version first", floor, version)}
	}
	return nil
}
