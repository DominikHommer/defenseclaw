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

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestAWaitingSwitchChecksAgainUnderTheAccountsDrain: settlePending read
// busy=0, then stopped the account's daemon and gateway with no check
// between; a sandbox that started and completed in that window
// (stop-sandboxes skips a completed one) was ended with the gateway, its
// MicroVM with no flush. Every change that stops the gateway (the pin
// migration's switch, sandboxes turned off) now runs under the account's
// drain: the drain checks again under the account's lifecycle lock, and a
// refusal keeps the change waiting, with nothing stopped. Once the drain
// holds, the units stop inside it, and it is let go after.
func TestAWaitingSwitchChecksAgainUnderTheAccountsDrain(t *testing.T) {
	old := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.3"}
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, old)))
	st := h.env.loadOpenShellState()
	st.Applied.Version = "0.1.3"
	if err := h.env.saveOpenShellState(st); err != nil {
		t.Fatal(err)
	}
	h.installTarballFiles(t, h.alice, "0.1.3")
	// The status says nothing runs: then a MicroVM starts and completes.
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	h.ops.onDrain = func(a SandboxAccount) error {
		return fmt.Errorf("%w (1 MicroVM run as this account, which the gateway's stop would end with no flush); stop them, then try again", openshell.ErrUnflushed)
	}
	ensure := func() *enterprisestatus.Result {
		r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.4"), ConfigFile: writeTempConfig(t, sandboxConfig(t, "linux", true, old))})
		requireOK(t, r)
		return r
	}
	r := ensure()
	if containsLine(r.Changes, "switched the sandbox setup of alice") || len(h.ops.stopped()) != 0 {
		t.Fatalf("switched under a MicroVM started after the status: changes %v, stops %v", r.Changes, h.ops.stopped())
	}
	entry, waiting := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]
	if !waiting || entry.Kind != "switch" || entry.Sandboxes != -1 || !strings.Contains(entry.Reason, "1 MicroVM run as this account") {
		t.Fatalf("pending = %+v, %v", entry, waiting)
	}
	if w := messagesOf(r.Warnings, codeSandboxPending); !strings.Contains(w, "the switch change for alice waits") {
		t.Errorf("warnings = %v", r.Warnings)
	}
	if !slices.Equal(h.ops.order, []string{"drain refused alice"}) {
		t.Fatalf("order = %v", h.ops.order)
	}

	// It has stopped: the drain holds, and the switch runs inside it.
	h.ops.onDrain, h.ops.order = nil, nil
	r = ensure()
	if !containsLine(r.Changes, `switched the sandbox setup of alice (version "0.1.3" -> "`+openshell.InstallerVersion+`")`) {
		t.Fatalf("changes = %v", r.Changes)
	}
	if !slices.Equal(h.ops.order, []string{"drain alice", "stop alice:daemon+gateway", "release alice"}) {
		t.Fatalf("order = %v", h.ops.order)
	}

	// Sandboxes turned off stops the gateway too: the same drain.
	h2 := newOSHost(t, "linux")
	on := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5"}
	requireOK(t, h2.ensure(sandboxConfig(t, "linux", true, on)))
	h2.ops.status[h2.alice.UID] = SandboxStatus{Active: true}
	h2.ops.onDrain = func(SandboxAccount) error { return errors.New("gateway openshell: a sandbox is starting") }
	requireOK(t, h2.ensure(sandboxConfig(t, "linux", false, on)))
	if entry := h2.env.loadOpenShellState().Pending[fmt.Sprint(h2.alice.UID)]; entry.Kind != "stop" || len(h2.ops.stopped()) != 0 {
		t.Fatalf("pending = %+v, stops %v", entry, h2.ops.stopped())
	}
	h2.ops.onDrain, h2.ops.order = nil, nil
	requireOK(t, h2.ensure(sandboxConfig(t, "linux", false, on)))
	if !slices.Equal(h2.ops.order, []string{"drain alice", "stop alice:daemon+gateway+socket", "release alice"}) {
		t.Fatalf("order = %v", h2.ops.order)
	}
}

// TestCommandOpsDrain: the drain runs as the account and holds until the
// lifecycle lets it go; one that refuses says why, and one that does not
// answer in time is ended.
func TestCommandOpsDrain(t *testing.T) {
	restore := drainCommand
	t.Cleanup(func() { drainCommand = restore })
	marker := filepath.Join(t.TempDir(), "released")
	var argv []string
	script := ""
	drainCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		argv = append([]string{name}, args...)
		return exec.CommandContext(ctx, "/bin/sh", "-c", script)
	}
	o := &commandUserOps{env: &Env{GOOS: "linux", Layout: managed.StandaloneLayout{BinDir: "/opt/defenseclaw/bin"}}}
	alice := SandboxAccount{Name: "alice", UID: 1001, Home: "/home/alice"}

	script = "echo '" + openshell.LifecycleDrained + "'; cat >/dev/null; touch " + marker
	release, err := o.Drain(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"runuser", "-u", "alice", "--", "/usr/bin/env", "HOME=/home/alice"}; !slices.Equal(argv[:len(want)], want) ||
		!slices.Equal(argv[len(argv)-3:], []string{"/opt/defenseclaw/bin/" + binGateway, "sandbox-daemon", "drain"}) {
		t.Fatalf("argv = %v", argv)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the drain let go before the lifecycle was done")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the drain was not let go: %v", err)
	}

	script = "echo 'openshell: the gateway was not restarted: dc-x (completed)' >&2; exit 1"
	if _, err := o.Drain(context.Background(), alice); err == nil || !strings.Contains(err.Error(), "dc-x (completed)") {
		t.Fatalf("a refused drain = %v", err)
	}

	wait := drainReadyWait
	t.Cleanup(func() { drainReadyWait = wait })
	drainReadyWait = 100 * time.Millisecond
	script = "sleep 30"
	start := time.Now()
	if _, err := o.Drain(context.Background(), alice); err == nil || !strings.Contains(err.Error(), "did not answer") || time.Since(start) > 10*time.Second {
		t.Fatalf("a drain that does not answer = %v after %s", err, time.Since(start))
	}
}
