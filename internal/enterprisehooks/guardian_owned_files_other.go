// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import "os"

func ownedFileStateFingerprint(path string, info os.FileInfo) string {
	return ownedFileContentFingerprint(path, info)
}
