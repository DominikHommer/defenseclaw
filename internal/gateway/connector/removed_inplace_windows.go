// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import "os"

// removedMayWriteInPlace is false on Windows: a hard-linked script gets the
// rename (removed.go). No release wrote an OpenHands script there (its
// hooks.json runs the native launcher, which blocks), and an OmniGent module
// under another name is blocked by the retired gateway route and the
// revoked token. until 1.1.
func removedMayWriteInPlace(os.FileInfo, os.FileInfo) bool { return false }
