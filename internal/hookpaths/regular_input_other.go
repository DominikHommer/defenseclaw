//go:build !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "os"

func openRegularNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
