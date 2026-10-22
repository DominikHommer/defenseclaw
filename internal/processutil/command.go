// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package processutil creates noninteractive subprocesses whose standard
// streams are captured by DefenseClaw.
package processutil

import (
	"context"
	"errors"
	"os/exec"
)

// CommandContext is equivalent to exec.CommandContext with platform-specific
// configuration for a captured background process.
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	configureCapturedCommand(cmd)
	return cmd
}

// CombinedOutputTree captures cmd's combined output. On Windows, cancellation
// and command completion terminate every non-breakaway descendant through a
// kill-on-close Job Object. On other platforms, it is equivalent to
// cmd.CombinedOutput and does not guarantee descendant cleanup.
//
// allowManagedBreakaway is reserved for trusted launchers whose separately
// identity-checked daemon must intentionally survive the short-lived command.
func CombinedOutputTree(cmd *exec.Cmd, allowManagedBreakaway bool) ([]byte, error) {
	return combinedOutputTree(cmd, allowManagedBreakaway)
}

// RunTree runs cmd with the streams the caller set and ties it to this
// process: on Windows a kill-on-close Job Object ends the whole tree. On
// Linux and macOS the child runs in a process group of its own, and the
// group is killed when the child exits, when cmd is canceled and when this
// process dies, also when it ends with os.Exit; on Linux the child also gets
// SIGKILL when this process dies. A killed gateway left its skill-scanner
// running at full CPU, and a second one started for the same skill after the
// restart (GAP-0418); a managed hook that exited once its answer was out
// left the tools it had started running (G-small); a Hermes hook Verify
// probed on macOS left the child it started running (r104 W5b). A
// descendant that leaves the group (setsid, setpgid) is not followed; use
// RunContained when the result must prove that nothing is left. Other
// platforms run cmd as is.
func RunTree(cmd *exec.Cmd) error {
	return runTree(cmd, false)
}

// ErrNotContained reports that RunContained could not establish that the
// command left nothing running.
var ErrNotContained = errors.New("processutil: could not establish that the command left nothing running")

// RunContained is RunTree for a command whose success counts only when
// nothing it started outlives it. A Hermes hook that Verify probed could
// start a child in a session of its own (setsid), out of the process group
// RunTree kills, and Verify passed while the child kept running (r104 W5b).
//
// On Linux a child-subreaper supervisor follows every descendant, also one
// that left the group or session, and kills and reaps them all; when it
// cannot, RunContained returns ErrNotContained. macOS has no subreaper: a
// descendant outside the group that kept an inherited descriptor fails the
// run with ErrNotContained, and one that also closed its descriptors is not
// seen. On Windows it is RunTree: the Job Object refuses breakaway. Other
// platforms never run cmd and return ErrNotContained.
//
// cmd must not have been started. On Linux, cmd.Cancel asks the supervisor
// to end the tree; set cmd.WaitDelay to bound the wait for it.
func RunContained(cmd *exec.Cmd) error {
	return runContained(cmd)
}
