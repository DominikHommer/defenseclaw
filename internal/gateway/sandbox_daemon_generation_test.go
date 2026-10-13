// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// es-demo:GAP-0012: a running managed sandbox took the administrator's new
// policy 20-35 s after the ensure reported it applied: a relayed answer's
// newer generation refreshed only the managed settings, and the running
// sandboxes' live fields (the egress lists the proxy enforces) waited for
// the next minute's policy/current poll. A newer generation now polls every
// live registration at once, for a tightened and a loosened policy alike.
func TestSandboxDaemonNewGenerationAppliesTheLiveFieldsAtOnce(t *testing.T) {
	f := newSandboxDaemonFixture(t) // policy poll and checks: once an hour
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Digest: "sha256:v1", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	live := sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 9, Digest: "sha256:v2", Live: live}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = f.d.superviseLoop(ctx, make(chan error))
	}()
	defer func() {
		cancel()
		<-done
	}()
	wait := func(digest string, block []string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if r, _ := f.d.regs.get("dc-a"); r.Digest == digest && len(r.Floor.EgressBlock) == len(block) {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		r, _ := f.d.regs.get("dc-a")
		t.Fatalf("the live fields did not follow generation change: %+v", r)
	}
	// Tightened: github.com blocked.
	f.d.observeGeneration(9)
	wait("sha256:v2", live.EgressBlock)
	// Loosened again.
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 10, Digest: "sha256:v3"}, nil
	}
	f.d.observeGeneration(10)
	wait("sha256:v3", nil)
}
