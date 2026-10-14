// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestWorkingDirectoryPathAliases(t *testing.T) {
	skipWindowsShellFixture(t)
	cwd, home := "/tmp/project", "/tmp/home"
	for _, row := range []struct{ command, target string }{
		{"echo x >> /proc/self/cwd/disklink", "disklink"},
		{"echo x >> /proc/thread-self/cwd/disklink", "disklink"},
		{"echo x >> ~+/disklink", "disklink"},
		{"echo x >> /proc/self/root/tmp/project/disklink", "disklink"},
		{"echo x >> /proc/self/cwd/out/log", "out/log"},
		{"echo x >> ~+/out/log", "out/log"},
	} {
		t.Run(row.command, func(t *testing.T) {
			paths, parsed, _ := ShellWriteOperands(row.command, cwd, home)
			if !parsed || !slices.Contains(paths, filepath.Join(cwd, row.target)) {
				t.Errorf("paths=%v parsed=%v", paths, parsed)
			}
		})
	}
}

func TestSameUserLauncherValue(t *testing.T) {
	skipWindowsShellFixture(t)
	cwd, home := "/tmp/project", "/tmp/home"
	for _, command := range []string{
		"sudo -n -u $USER tee -a disklink",
		"sudo -n -u $LOGNAME tee -a disklink",
		"sudo -n -u $(whoami) tee -a disklink",
		"sudo -n -u $(id -un) tee -a disklink",
	} {
		t.Run(command, func(t *testing.T) {
			var paths []string
			for _, operand := range ShellExtraWriteOperands(command, cwd, home) {
				paths = append(paths, operand.Path)
			}
			if !slices.Contains(paths, filepath.Join(cwd, "disklink")) {
				t.Errorf("paths=%v", paths)
			}
		})
	}
}
