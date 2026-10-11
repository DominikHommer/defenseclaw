// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A hard link is compared by file identity (inode, or volume serial and file
// index on Windows), not by its own pathname.
func TestResolveHardLinkToAuthorizedKeys(t *testing.T) {
	// macOS keeps the temp dir under the /var -> /private/var link.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link, other := filepath.Join(home, "hard.cfg"), filepath.Join(home, "notes.txt")
	if err := os.Link(keys, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(home)
	for path, want := range map[string]string{link: keys, other: other} {
		payload, err := json.Marshal(map[string]any{"tool_name": "Write",
			"tool_input": map[string]any{"file_path": path, "content": "marker"}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(payload))
		if !ok || targets[path] != want {
			t.Fatalf("target of %s = %q, want %q; all=%v", path, targets[path], want, targets)
		}
	}
}

// A wrapper in front of apply_patch still runs it with a patch the hook
// cannot read, so its targets are unknown; an unresolved wrapper that names
// apply_patch fails closed too (GAP-1428).
func TestApplyPatchBehindWrapperIsUnknown(t *testing.T) {
	for command, known := range map[string]bool{
		"env apply_patch < draft.patch": false,
		"echo '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch'\napply_patch < staged.patch":        false,
		"printf '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch'\ncat staged.patch | apply_patch":  false,
		"printf '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch'; cat staged.patch | apply_patch":  false,
		"apply_patch '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch'; APPLY_PATCH < staged.patch": false,
		"printf '*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch' | apply_patch < staged.patch":     false,
		"env FOO=1 apply_patch < draft.patch":        false,
		"command apply_patch < draft.patch":          false,
		"exec apply_patch < draft.patch":             false,
		"nohup apply_patch < draft.patch":            false,
		"time apply_patch < draft.patch":             false,
		"nice -n 5 apply_patch < draft.patch":        false,
		"sudo apply_patch < draft.patch":             false,
		`sh -c "apply_patch < draft.patch"`:          false,
		"sudo --user root apply_patch < draft.patch": false,
		"time grep -rn apply_patch .":                true,
		"env FOO=1 make test":                        true,
	} {
		if targets, ok := ApplyPatchWriteTargets("Bash", nil, command, "", ""); ok != known || len(targets) != 0 {
			t.Errorf("%s: targets %v, known %v; want known %v", command, targets, ok, known)
		}
	}
}

func TestApplyPatchBoundEnvelopeInputs(t *testing.T) {
	envelope := "*** Begin Patch\n*** Update File: /tmp/notes.txt\n@@\n+x\n*** End Patch"
	for _, command := range []string{
		"apply_patch <<'PATCH'\n" + envelope + "\nPATCH",
		"apply_patch <<< '" + envelope + "'",
		"apply_patch '" + envelope + "'",
		"echo '" + envelope + "' | apply_patch",
		"@'\n" + envelope + "\n'@ | apply_patch",
	} {
		targets, ok := ApplyPatchWriteTargets("Bash", nil, command, "", "")
		if !ok || len(targets) != 1 || targets[0] != "/tmp/notes.txt" {
			t.Errorf("%q: targets %v, known %v", command, targets, ok)
		}
	}
}
