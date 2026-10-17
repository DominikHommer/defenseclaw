// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterpriseunix

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// bootoutRunner answers ps with the uids of running processes and
// launchctl bootout from a set of loaded jobs.
type bootoutRunner struct {
	Runner
	ps     string
	mu     *sync.Mutex
	loaded map[string]bool
	broken map[string]bool
	calls  *[]string
}

func (r bootoutRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "ps" && strings.Join(args, " ") == "-axo uid=" {
		return CommandResult{Stdout: []byte(r.ps)}, nil
	}
	if name == "launchctl" && len(args) == 2 && args[0] == "bootout" {
		r.mu.Lock()
		defer r.mu.Unlock()
		*r.calls = append(*r.calls, args[1])
		switch {
		case r.loaded[args[1]]:
			delete(r.loaded, args[1])
			return CommandResult{}, nil
		case r.broken[args[1]]:
			return CommandResult{ExitCode: 5, Stderr: []byte("Boot-out failed: 5: Input/output error")}, errors.New("launchctl bootout: exit 5")
		case strings.HasPrefix(args[1], "gui/"):
			return CommandResult{ExitCode: 125, Stderr: []byte("Domain does not support specified action")}, errors.New("launchctl bootout: exit 125")
		}
		return CommandResult{ExitCode: 3, Stderr: []byte("No such process")}, errors.New("launchctl bootout: exit 3: No such process")
	}
	return r.Runner.Run(ctx, name, args...)
}

// #1210: launchd loads both sandbox LaunchAgents for every account that
// signs in, and Stop boots out only one domain of an account. The uninstall
// boots them out of the gui and user domains of every account that runs a
// process, before their plists and binary go, and names any it could not.
func TestUninstallBootsTheSandboxAgentsOutOfEverySignedInAccount(t *testing.T) {
	h := newOSHost(t, "darwin")
	requireOK(t, h.ensure(sandboxConfig(t, "darwin", true, setupVMSettings)))
	var calls []string
	runner := bootoutRunner{
		Runner: h.env.Runner,
		ps:     "    0\n   88\n  501\n  502\n  501\n4294967294\n",
		mu:     &sync.Mutex{},
		loaded: map[string]bool{
			"user/502/" + labelSandbox:         true,
			"gui/501/" + labelOpenShellGateway: true,
		},
		broken: map[string]bool{"user/501/" + labelSandbox: true},
		calls:  &calls,
	}
	h.env.Runner = runner
	r := h.run(Options{Action: ActionUninstall})
	requireOK(t, r)
	for _, call := range calls {
		if !strings.HasPrefix(call, "gui/501/") && !strings.HasPrefix(call, "user/501/") &&
			!strings.HasPrefix(call, "gui/502/") && !strings.HasPrefix(call, "user/502/") {
			t.Fatalf("booted out a system account's domain: %v", calls)
		}
	}
	if len(runner.loaded) != 0 {
		t.Fatalf("still loaded: %v (calls %v)", runner.loaded, calls)
	}
	if !containsLine(r.Changes, "unloaded the DefenseClaw sandbox LaunchAgents of the signed-in accounts (gui/501/"+labelOpenShellGateway+", user/502/"+labelSandbox+")") {
		t.Fatalf("changes = %v", r.Changes)
	}
	if got := messagesOf(r.Warnings, codeSandboxUserState); !strings.Contains(got, "could not unload user/501/"+labelSandbox) {
		t.Fatalf("the job that could not be unloaded is not named: %q", got)
	}
}

// The macOS pkg installs both LaunchAgents with the sandbox subsystem off,
// so a package that never turned sandboxes on has no sandbox state, yet
// launchd loads the agents for every account that signs in. Its uninstall
// boots them out too, before their plists go.
func TestUninstallBootsTheAgentsOfAPackageWithSandboxesOffOut(t *testing.T) {
	h := newOSHost(t, "darwin")
	agents := writeMacOSPackageFiles(t, h)
	requireOK(t, ensureFromMacOSPackage(t, h, sandboxConfig(t, "darwin", false, nil)))
	if state := h.env.loadOpenShellState(); state.Applied != nil || len(state.Pending) != 0 {
		t.Fatalf("a package with sandboxes off recorded sandbox state %+v", state)
	}
	var calls []string
	runner := bootoutRunner{
		Runner: h.env.Runner,
		ps:     "  0\n 501\n",
		mu:     &sync.Mutex{},
		loaded: map[string]bool{
			"gui/501/" + labelSandbox:          true,
			"gui/501/" + labelOpenShellGateway: true,
		},
		calls: &calls,
	}
	h.env.Runner = runner
	r := h.run(Options{Action: ActionUninstall})
	requireOK(t, r)
	if len(runner.loaded) != 0 {
		t.Fatalf("still loaded: %v (calls %v)", runner.loaded, calls)
	}
	if !containsLine(r.Changes, "unloaded the DefenseClaw sandbox LaunchAgents of the signed-in accounts (gui/501/"+labelSandbox+", gui/501/"+labelOpenShellGateway+")") {
		t.Fatalf("changes = %v", r.Changes)
	}
	for _, path := range agents {
		if h.exists(path) {
			t.Errorf("%s stays after uninstall", path)
		}
	}
}
