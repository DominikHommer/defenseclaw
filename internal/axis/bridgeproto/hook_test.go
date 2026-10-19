// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeproto

import (
	"strings"
	"testing"
)

func TestTypedHookRequiresExactSessionAndOneFixedReadSlot(t *testing.T) {
	baseline, binding := preparationFixture(t)
	baselineHash := binding.PreparationHash
	if baselineHash != "sha256:2b70112993942ea7aecfe3d146550fcda20a7de01f9646e5223e07f637ae9174" {
		t.Fatal("absent hook changed the reviewed v1 preparation hash")
	}
	profile := "sha256:" + strings.Repeat("a", 64)
	plan := baseline
	plan.Filesystem.Read = append(append([]string{}, baseline.Filesystem.Read...), HookDirectory)
	plan.Hook = &Hook{SessionID: binding.SessionID, ReadIndex: 1, ProfileDigest: profile}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	binding.PreparationHash, _ = PreparationDigest(plan)
	if binding.PreparationHash != "sha256:8a3ccd0c445a94ebb2b56a4147c9297330fe6d6012167ff845b1fc73a12344db" {
		t.Fatal("independent typed-hook digest vector differs")
	}
	if binding.PreparationHash == baselineHash || (Frame{Version: Version, Sequence: 1, Request: 1, Binding: binding, Kind: Prepare, Plan: &plan}).Validate() != nil {
		t.Fatal("typed hook did not bind the preparation frame")
	}
	wrong := plan
	wrong.Hook = &Hook{SessionID: "other-session", ReadIndex: 1, ProfileDigest: profile}
	wrongBinding := binding
	wrongBinding.PreparationHash, _ = PreparationDigest(wrong)
	if (Frame{Version: Version, Sequence: 1, Request: 1, Binding: wrongBinding, Kind: Prepare, Plan: &wrong}).Validate() == nil {
		t.Fatal("binding mismatch admitted")
	}
	for _, mutation := range []func(*Preparation){
		func(p *Preparation) { p.Hook = nil },
		func(p *Preparation) { p.Hook.ReadIndex = 0 },
		func(p *Preparation) { p.Hook.ProfileDigest = "sha256:invalid" },
		func(p *Preparation) { p.Filesystem.Read[1] = HookSocket },
		func(p *Preparation) { p.Filesystem.Write = append(p.Filesystem.Write, HookDirectory) },
		func(p *Preparation) { p.Filesystem.Read = append(p.Filesystem.Read, "/run") },
		func(p *Preparation) { p.Filesystem.Read = append(p.Filesystem.Read, "/") },
		func(p *Preparation) { p.Filesystem.Write = append(p.Filesystem.Write, "/") },
		func(p *Preparation) { p.Workdir = "/" },
		func(p *Preparation) { p.Backend = "seatbelt" },
		func(p *Preparation) {
			p.Environment = append(p.Environment, Variable{Name: "DEFENSECLAW_HOOK_SOCKET", Value: HookSocket})
		},
	} {
		changed := plan
		changed.Filesystem.Read = append([]string{}, plan.Filesystem.Read...)
		changed.Filesystem.Write = append([]string{}, plan.Filesystem.Write...)
		changed.Environment = append([]Variable{}, plan.Environment...)
		copy := *plan.Hook
		changed.Hook = &copy
		mutation(&changed)
		if changed.Validate() == nil {
			t.Fatal("partial or substituted hook capability admitted")
		}
	}
}
