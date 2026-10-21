// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

// ConfirmedProductFloor is the min_product_version of the confirmed bundle:
// the lowest DefenseClaw release the device may run while that bundle
// enforces. It is "" when no bundle is confirmed or the bundle sets none. A
// stored bundle that no longer checks out is an error.
func (s *Store) ConfirmedProductFloor() (string, error) {
	st, err := s.LoadState()
	if err != nil {
		return "", err
	}
	if st.Current == nil {
		return "", nil
	}
	b, err := s.ReadVersion(st.Current)
	if err != nil {
		return "", err
	}
	m, err := DecodeManifest(b.Manifest)
	if err != nil {
		return "", err
	}
	return m.MinProductVersion, nil
}
