// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "os"

func openNativeStateFile(path string) (*os.File, error) { return os.Open(path) }

// POSIX opens and reads have no sharing modes, so nothing is ever busy.
func nativeStateFileBusy(error) bool { return false }

func nativeStateFileHolders(string) []string { return nil }
