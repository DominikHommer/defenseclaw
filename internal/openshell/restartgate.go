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

package openshell

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// VMGone reports OpenShell's account of a sandbox in its error state whose
// MicroVM no longer runs (said is FailureReason's, or a record's
// PhaseReason): the vm driver's ProcessExited, which it sets once the VM
// process or its host supervisor exited, and then ends the other, and for
// a sandbox whose main process had exited before the driver restarted,
// which it restores without launching its VM (0.1.3 and 0.1.5). Nothing of
// such a sandbox runs, so a stop of its gateway ends nothing.
func VMGone(said string) bool {
	return saysReason(said, "ProcessExited")
}

// mainProcessFailed reports OpenShell's account of a sandbox in its error
// state because its main process exited with an error (said: as for
// VMGone): OpenShell returns its stop as it is (is_failed_main_process_result,
// 0.1.3 and 0.1.5), and starts it again.
func mainProcessFailed(said string) bool {
	return saysReason(said, "MainProcessFailed")
}

// saysReason reports whether said (FailureReason's "Reason: message; ..."
// or a bare reason) gives the condition reason reason.
func saysReason(said, reason string) bool {
	for _, part := range strings.Split(said, "; ") {
		if part == reason || strings.HasPrefix(part, reason+":") {
			return true
		}
	}
	return false
}

// HoldsGateway reports whether a sandbox that OpenShell lists in phase p
// (said: as for VMGone) keeps DefenseClaw from stopping, restarting or
// upgrading its gateway, or from moving its account to another OpenShell
// setup. Any of those stops every sandbox on the gateway, and where the
// compute driver's stop does not keep what a workload has not synced
// (stopFlushes false: the MicroVM driver, whose VMs end with the gateway,
// and a driver DefenseClaw does not know) a VM that still runs loses what
// it wrote last.
//
// Only OpenShell's own state releases a sandbox: it is stopped, it is
// being deleted, or it is in the error state because its VM process
// exited (VMGone). Nothing else does: not the time since its workload
// ended, nor a stop DefenseClaw asked for that OpenShell did not make.
// Ready, provisioning, starting, stopping, unknown and unnamed phases
// hold, and so do completed and every other error state (a main process
// that failed, a VM process OpenShell could not poll, a provisioning that
// timed out, an image that failed, no reason given): the VM keeps running
// after its main process ends (GAP-0012), with whatever that process left
// running, and nothing in OpenShell flushes it. On a driver whose stop
// keeps the workload's writes (docker: an exited container), the ended
// phases hold nothing.
func HoldsGateway(p SandboxPhase, said string, stopFlushes bool) bool {
	switch p {
	case PhaseStopped, PhaseDeleting:
		return false
	case PhaseCompleted:
		return !stopFlushes
	case PhaseError:
		return !stopFlushes && !VMGone(said)
	}
	return true
}

// StopWayOn is what the user runs to bring the sandbox name, which holds
// its gateway in phase p (HoldsGateway; said: as for VMGone), to a phase in
// which OpenShell reports it stopped, on a gateway that runs DefenseClaw
// sandboxes (runs: SandboxMin or later) or an older one, whose stop of a
// sandbox in its error state OpenShell refuses and on which DefenseClaw
// starts none. OpenShell returns its stop of a completed sandbox, or of
// one whose main process failed, as it is, and refuses the stop of one
// whose provisioning timed out: a start, then the stop of the ready
// sandbox (which flushes it), brings those to stopped.
func StopWayOn(name string, p SandboxPhase, said string, runs bool) string {
	stop := "`defenseclaw sandbox stop " + name + "`"
	del := "`defenseclaw sandbox delete " + name + "`, which deletes it and its work"
	startStop := "`defenseclaw sandbox start " + name + "`, then " + stop + " once it is ready"
	switch {
	case p == PhaseReady:
		return stop
	case p != PhaseCompleted && p != PhaseError:
		return "wait until `defenseclaw sandbox list` shows it ready or stopped, then " + stop + " if it is ready"
	case !runs && p == PhaseCompleted:
		return del + " (this OpenShell neither stops nor starts a completed MicroVM)"
	case !runs:
		return del + " (this OpenShell neither stops nor starts a sandbox in its error state)"
	case p == PhaseError && ProvisioningTimedOut(said):
		return "wait a minute for OpenShell's cleanup of the provisioning that timed out, then " + startStop +
			" (OpenShell refuses to stop a sandbox whose provisioning timed out), or " + del
	case p == PhaseCompleted || mainProcessFailed(said):
		return startStop + " (OpenShell does not stop a MicroVM whose main process ended, and the start ends what that left running), or " + del
	}
	return stop
}

// phaseWord is p as OpenShell's lower-case name ("unknown" for none).
func phaseWord(p SandboxPhase) string {
	if p == "" {
		return "unknown"
	}
	return strings.ToLower(string(p))
}

// stoppedRefusal is base for the sandboxes of list that hold their gateway
// on a driver whose stop does not flush (HoldsGateway), each named with
// its phase and its way on (StopWayOn, on a gateway that runs sandboxes
// when runs says so; asked only when one holds), and then is the step to
// retry after; nil when none holds.
func stoppedRefusal(base error, list []*Sandbox, runs func() bool, then string) error {
	var held []*Sandbox
	for _, sb := range list {
		if sb != nil && HoldsGateway(sb.Status.Phase, FailureReason(sb), false) {
			held = append(held, sb)
		}
	}
	if len(held) == 0 {
		return nil
	}
	newer := runs()
	lines := make([]string, 0, len(held))
	for _, sb := range held {
		lines = append(lines, fmt.Sprintf("%s (%s): %s", sb.Name, phaseWord(sb.Status.Phase), StopWayOn(sb.Name, sb.Status.Phase, FailureReason(sb), newer)))
	}
	slices.Sort(lines)
	return fmt.Errorf("%w; OpenShell has not reported these stopped: %s; then %s", base, strings.Join(lines, "; "), then)
}

// gatewayRunsSandboxes reports whether the gateway c talks to runs
// DefenseClaw sandboxes (RunsSandboxes of its health's release): false
// when it does not say.
func gatewayRunsSandboxes(ctx context.Context, c Client) bool {
	h, err := c.Health(ctx)
	return err == nil && h != nil && RunsSandboxes(h.RawVersion)
}
