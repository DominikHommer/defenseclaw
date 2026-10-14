// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"path/filepath"
	"testing"
)

// The administrator's e2fsprogs_dir may be the install prefix (tools in its
// sbin or bin) or the folder that holds the tools; the folder returned holds
// both, and nothing else is accepted (GAP-0506).
func TestAdminE2fsprogsToolDir(t *testing.T) {
	files := func(paths ...string) func(string) bool {
		set := map[string]bool{}
		for _, p := range paths {
			set[filepath.FromSlash(p)] = true
		}
		return func(p string) bool { return set[p] }
	}
	prefix := "/opt/cisco/defenseclaw-deps/e2fsprogs"
	cases := []struct {
		name, dir string
		isFile    func(string) bool
		want      string
	}{
		{"prefix with sbin", prefix, files(prefix+"/sbin/mke2fs", prefix+"/sbin/debugfs"), prefix + "/sbin"},
		{"prefix with bin", prefix, files(prefix+"/bin/mke2fs", prefix+"/bin/debugfs"), prefix + "/bin"},
		// The rc.1 wave's configuration: the sbin folder itself.
		{"the tool folder", prefix + "/sbin", files(prefix+"/sbin/mke2fs", prefix+"/sbin/debugfs"), prefix + "/sbin"},
		{"tools split over sbin and bin", prefix, files(prefix+"/sbin/mke2fs", prefix+"/bin/debugfs"), ""},
		{"debugfs missing", prefix, files(prefix + "/sbin/mke2fs"), ""},
		{"empty", "", files(), ""},
	}
	for _, c := range cases {
		if got := AdminE2fsprogsToolDir(filepath.FromSlash(c.dir), c.isFile); got != filepath.FromSlash(c.want) {
			t.Errorf("%s: AdminE2fsprogsToolDir(%q) = %q, want %q", c.name, c.dir, got, c.want)
		}
	}
}
