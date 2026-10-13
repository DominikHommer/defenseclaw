// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestUnresolvedProgramWordProof(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	linked := filepath.Join(cwd, "next.txt")
	for _, command := range []string{
		`P=ln; $P -s ~/.ssh/authorized_keys next.txt && echo ok >> next.txt`,
		`P=ln; "$P" -s ~/.ssh/authorized_keys next.txt && echo ok >> next.txt`,
		`$(printf ln) -s ~/.ssh/authorized_keys next.txt && echo ok >> next.txt`,
	} {
		if !CommandLinksWithFacts("Bash", command, cwd, home, nil).OpaqueTarget(linked) {
			t.Errorf("unresolved program has no later-write scope: %q", command)
		}
	}
	paths, unknown := LiteralWriteAnalysis(`P=python3; "$P" -c 'open("disklink","a").write("ok")'`, cwd, home)
	if unknown || !slices.Contains(paths, filepath.Join(cwd, "disklink")) {
		t.Fatalf("bounded program paths = %v, unknown = %v", paths, unknown)
	}
	paths, unknown = LiteralWriteAnalysis(`P=cat; eval P=python3; "$P" -c 'open("disklink","a").write("ok")'`, cwd, home)
	if unknown || !slices.Contains(paths, filepath.Join(cwd, "disklink")) {
		t.Fatalf("changed program paths = %v, unknown = %v", paths, unknown)
	}
}
