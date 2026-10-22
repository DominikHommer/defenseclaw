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
	path := writeTestConfig(t, "deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\nguardrail:\n  mode: observe\nobservability: {}\n")
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

// W4b loop round 1: the lifecycle's Locked path (the Windows config step a
// Codex repair or an equal-byte bundle upgrade runs, the Unix bundle record)
// binds bytes already in place through the record alone. Over a record that
// is there but cannot be read it refuses and leaves the record as it was; a
// write of new bytes, a missing record and a write without a bundle still
// record, as before.
func TestLockedRefusesBundleBindingOverUnreadableGeneration(t *testing.T) {
	bundle := Options{Actor: "operator:test", Lifecycle: true,
		Bundle: BundleRef{ID: "b-01J9ZZZZZZZZZZZZZZZZZZZZZZ", Version: 1, SignerKeyID: "k1"}}
	lifecycle := Options{Actor: ActorLifecycle, Reason: "enterprise windows ensure"}
	corrupt := func(t *testing.T, path string) []byte {
		raw := []byte(`{"generation":7,`)
		if err := os.WriteFile(GenerationPath(path), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	unreadable := func(t *testing.T, path string) []byte {
		// A directory where the record belongs: there, but no record can be read.
		if err := os.Mkdir(GenerationPath(path), 0o700); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	for _, tc := range []struct {
		name    string
		opt     Options
		damage  func(*testing.T, string) []byte
		rewrite bool
		refuse  bool
	}{
		{name: "bundle over corrupt record", opt: bundle, damage: corrupt, refuse: true},
		{name: "bundle over unreadable record", opt: bundle, damage: unreadable, refuse: true},
		{name: "bundle writing new bytes over corrupt record", opt: bundle, damage: corrupt, rewrite: true},
		{name: "bundle without a record", opt: bundle},
		{name: "lifecycle over corrupt record", opt: lifecycle, damage: corrupt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestConfig(t, "deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\nobservability: {}\n")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var before []byte
			if tc.damage != nil {
				before = tc.damage(t, path)
			}
			_, err = Locked(context.Background(), path, tc.opt, func() (bool, error) {
				if tc.rewrite {
					return true, os.WriteFile(path, append(raw, []byte("# bundle\n")...), 0o600)
				}
				return true, nil
			})
			if tc.refuse {
				if !errors.Is(err, ErrUnprovenBundleBinding) || !strings.Contains(err.Error(), "enterprise bundle status --json") {
					t.Fatalf("Locked over unproven generation: %v", err)
				}
				if before != nil {
					if after, readErr := os.ReadFile(GenerationPath(path)); readErr != nil || string(after) != string(before) {
						t.Fatalf("refusal rewrote the record: %q, %v", after, readErr)
					}
				} else if info, statErr := os.Stat(GenerationPath(path)); statErr != nil || !info.IsDir() {
					t.Fatalf("refusal replaced the unreadable record: %v", statErr)
				}
				if after, _ := os.ReadFile(path); string(after) != string(raw) {
					t.Fatalf("refusal changed config.yaml: %q", after)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			state, err := ReadGenerationState(path)
			if err != nil || state.BundleID != tc.opt.Bundle.ID || state.Actor != tc.opt.Actor {
				t.Fatalf("recorded %+v, %v", state, err)
			}
			if tc.damage != nil && (!state.GenerationReset || state.Generation != 8) {
				t.Fatalf("a reset over a corrupt record must say so and keep counting: %+v", state)
			}
		})
	}
}
