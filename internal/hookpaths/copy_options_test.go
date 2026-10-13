// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

func TestCopyDestinationScope(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	rows := []struct {
		name   string
		args   []string
		static []bool
		want   string
	}{
		{"dynamic source", []string{"$F", "out.txt"}, []bool{false, true}, "out.txt"},
		{"dynamic source after option terminator", []string{"--", "$F", "out.txt"}, []bool{true, false, true}, "out.txt"},
		{"dynamic protected name", []string{"$F", "authorized_keys"}, []bool{false, true}, ""},
		{"dynamic earlier protected name", []string{"$F", "authorized_keys", "out.txt"}, []bool{false, true, true}, ""},
		{"mac clone flag", []string{"-c", "report.txt", "r2.txt"}, makeStatic(3), "r2.txt"},
		{"mac metadata flag", []string{"-X", "report.txt", "r2.txt"}, makeStatic(3), "r2.txt"},
		{"mac name flag", []string{"-N", "report.txt", "r2.txt"}, makeStatic(3), "r2.txt"},
		{"context flag", []string{"-Z", "report.txt", "r2.txt"}, makeStatic(3), "r2.txt"},
		{"joined context", []string{"--context=system_u", "report.txt", "r2.txt"}, makeStatic(3), "r2.txt"},
		{"unknown option", []string{"--future-option", "report.txt", "r2.txt"}, makeStatic(3), ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := cpDestination(row.args, row.static, cwd)
			want := ""
			if row.want != "" {
				want = filepath.Join(cwd, row.want)
			}
			if got != want {
				t.Fatalf("destination = %q, want %q", got, want)
			}
		})
	}
	ordinary := `cp "$F" out.txt && echo ok > report.txt`
	if CommandLinksWithFacts("Bash", ordinary, cwd, home, nil).OpaqueTarget(filepath.Join(cwd, "report.txt")) {
		t.Fatal("copy scope includes an unrelated later write")
	}
	protected := `cp "$F" authorized_keys && echo ok > report.txt`
	if !CommandLinksWithFacts("Bash", protected, cwd, home, nil).OpaqueTarget(filepath.Join(cwd, "report.txt")) {
		t.Fatal("dynamic option scope is incomplete")
	}
}
