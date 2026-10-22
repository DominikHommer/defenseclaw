//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import "golang.org/x/sys/unix"

// publishedSessionVolumeIsReadOnly reports a path on a mount that is
// read-only (statfs ST_RDONLY, which covers a read-only bind mount too).
func publishedSessionVolumeIsReadOnly(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return st.Flags&unix.ST_RDONLY != 0, nil
}
