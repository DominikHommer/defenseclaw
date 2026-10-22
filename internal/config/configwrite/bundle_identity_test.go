// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package configwrite

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// GAP-0359: equal config bytes can move from the base policy to a signed
// bundle, or between bundles. The gateway must observe each new identity.
func TestEqualConfigBytesRecordANewBundleIdentity(t *testing.T) {
	path := writeTestConfig(t, "enterprise:\n  profile: standalone\nguardrail:\n  mode: observe\nobservability: {}\n")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{Actor: "operator:test", Lifecycle: true, ExpectSHA256: SHA256Hex(raw),
		Bundle: BundleRef{ID: "b-01J9ZZZZZZZZZZZZZZZZZZZZZZ", Version: 1, SignerKeyID: "k1"}}
	for step := 0; step < 4; step++ {
		switch step {
		case 1:
			opt.Bundle.Version++
		case 2:
			opt.Bundle.ID = "b-01J9ZZZZZZZZZZZZZZZZZZZZZY"
		case 3:
			opt.Bundle.SignerKeyID = "k2"
		}
		result, err := ReplaceDocument(context.Background(), path, raw, opt)
		if err != nil {
			t.Fatal(err)
		}
		state, err := ReadGenerationState(path)
		if err != nil || state.Generation != uint64(step+1) || result.Generation != state.Generation ||
			state.BundleID != opt.Bundle.ID || state.BundleVersion != opt.Bundle.Version || state.SignerKeyID != opt.Bundle.SignerKeyID {
			t.Fatalf("step %d: state=%+v result=%+v err=%v", step, state, result, err)
		}
		repeat, err := ReplaceDocument(context.Background(), path, raw, opt)
		if err != nil || repeat.Generation != result.Generation {
			t.Fatalf("repeat: %+v, %v", repeat, err)
		}
	}
	before, err := os.ReadFile(GenerationPath(path))
	if err != nil {
		t.Fatal(err)
	}
	opt.ExpectSHA256 = "wrong preimage"
	if _, err := ReplaceDocument(context.Background(), path, raw, opt); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale preimage: %v", err)
	}
	after, err := os.ReadFile(GenerationPath(path))
	if err != nil || string(after) != string(before) {
		t.Fatalf("refusal changed generation: %v", err)
	}
	// A failed first apply restores the base's identity even though its
	// bytes are identical to the refused bundle's.
	restored, err := ReplaceDocument(context.Background(), path, raw, Options{Actor: ActorLifecycle, ExpectSHA256: SHA256Hex(raw)})
	if err != nil {
		t.Fatal(err)
	}
	state, err := ReadGenerationState(path)
	if err != nil || restored.Generation != 5 || state.BundleID != "" || state.BundleVersion != 0 || state.SignerKeyID != "" {
		t.Fatalf("restored base: %+v, %v", state, err)
	}
	broken := []byte(`{"generation":5,`)
	if err := os.WriteFile(GenerationPath(path), broken, 0o600); err != nil {
		t.Fatal(err)
	}
	opt.ExpectSHA256 = SHA256Hex(raw)
	if _, err := ReplaceDocument(context.Background(), path, raw, opt); err == nil || !strings.Contains(err.Error(), "enterprise bundle status --json") {
		t.Fatalf("unproven generation: %v", err)
	}
	after, err = os.ReadFile(GenerationPath(path))
	if err != nil || string(after) != string(broken) {
		t.Fatalf("refusal rewrote the unproven generation: %q, %v", after, err)
	}
}
