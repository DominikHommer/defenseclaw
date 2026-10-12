// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"testing"
)

// FuzzReadArchive: any input either reads as a bundle within the limits, with
// only valid bundle paths, or is refused with a bundle error code.
func FuzzReadArchive(f *testing.F) {
	f.Add(archive(f, tree()...))
	f.Add(archive(f, append(tree(), file(ManifestName, "{}"), file(SignatureName, "{}"))...))
	f.Add(archive(f, file("../x", "")))
	f.Add([]byte{0x1f, 0x8b})
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := ReadArchive(bytes.NewReader(data))
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatalf("refusal without a bundle code: %v", err)
			}
			return
		}
		total := len(b.Manifest) + len(b.Signature)
		for name, body := range b.Files {
			if bad := checkBundlePath(name, false); bad != nil {
				t.Fatalf("accepted %q: %v", name, bad)
			}
			total += len(body)
		}
		if total > MaxExpandedBytes || len(b.Files) > MaxEntries {
			t.Fatalf("accepted %d bytes in %d files", total, len(b.Files))
		}
	})
}

// FuzzDecodeManifest: an accepted manifest re-encodes to bytes that decode to
// the same manifest; anything else is refused as manifest_invalid.
func FuzzDecodeManifest(f *testing.F) {
	valid := marshal(nil, validManifest())
	f.Add(valid)
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := DecodeManifest(raw)
		if err != nil {
			if CodeOf(err) != CodeManifestInvalid {
				t.Fatalf("refusal with code %q: %v", CodeOf(err), err)
			}
			return
		}
		once, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeManifest(once)
		if err != nil {
			t.Fatalf("re-encoded manifest refused: %v", err)
		}
		twice, err := again.Marshal()
		if err != nil || !bytes.Equal(once, twice) {
			t.Fatalf("re-encoding is not stable: %v", err)
		}
	})
}
