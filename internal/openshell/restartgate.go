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
	"strings"
)

// VMGone reports OpenShell's account of a sandbox in its error state whose
// MicroVM no longer runs (said is failureReason's, or a record's
// PhaseReason): the vm driver's ProcessExited, which it sets once the VM
// process or its host supervisor exited, and then ends the other, and for
// a sandbox whose main process had exited before the driver restarted,
// which it restores without launching its VM (0.1.3 and 0.1.5). Nothing of
// such a sandbox runs, so a stop of its gateway ends nothing.
func VMGone(said string) bool {
	for _, part := range strings.Split(said, "; ") {
		if part == "ProcessExited" || strings.HasPrefix(part, "ProcessExited:") {
			return true
		}
	}
	return false
}

// MayLinger reports a sandbox in phase p (said: as for VMGone) whose
// MicroVM may still run although no workload of it is known to: its main
// process completed or failed, or it is in the error state for any reason
// but a VM that is gone (VMGone) or a provisioning that timed out
// (ProvisioningTimedOut, nothing ran in it since its last stop). The VM
// keeps running after its main process ends (GAP-0012), and with it what
// that process left running, a background process it forked: nothing
// tells when that has written all it will, no OpenShell call flushes such
// a VM (ExecSandbox runs only in a ready sandbox, and the flush 0.1.5 makes
// before a stop, NVIDIA/OpenShell#4195, leaves out a sandbox whose main
// process exited), and OpenShell returns its stop of a completed one, or
// of one whose main process failed, as it was. A stop of its gateway may
// so lose what it wrote last, and what stops a gateway on its own waits
// for it until its user lets it go (StopsAsked) or deletes it.
func MayLinger(p SandboxPhase, said string) bool {
	switch p {
	case PhaseCompleted:
		return true
	case PhaseError:
		return !VMGone(said) && !ProvisioningTimedOut(said)
	}
	return false
}

// StopsAsked lists the sandboxes whose user asked DefenseClaw to stop them
// where OpenShell does not (MayLinger), by name, with the phase they were
// in then, lower case as OpenShell names it ("completed"): DefenseClaw's
// gateway restarts and upgrades let such a one go while it stays in that
// phase (LetGo), since that is the stop its user asked for. Its source is
// the user's DefenseClaw daemon (sandboxapi.Sandbox.StopAskedIn); nil, or
// a daemon that does not answer, lets none go.
type StopsAsked func(context.Context) map[string]string

// LetGo reports whether asked (a StopsAsked list) lets sb go: its user
// asked DefenseClaw to stop it in the phase it is still in.
func LetGo(asked map[string]string, sb *Sandbox) bool {
	if sb == nil {
		return false
	}
	ph, ok := asked[sb.Name]
	return ok && ph != "" && ph == strings.ToLower(string(sb.Status.Phase))
}

// stopsAsked is asked's list, nil for none.
func stopsAsked(ctx context.Context, asked StopsAsked) map[string]string {
	if asked == nil {
		return nil
	}
	return asked(ctx)
}

// restartRisk is what a restart of a gateway whose compute driver's stop
// keeps only what was flushed (the MicroVM driver, or one DefenseClaw
// does not know) does to one of its sandboxes.
type restartRisk int

const (
	// riskNone: nothing of it runs (stopped, deleting, its VM gone, or its
	// provisioning timed out: nothing ran in it since its last stop).
	riskNone restartRisk = iota
	// riskReady: it runs, and OpenShell's own stop of it flushes its
	// guest first from SandboxMin on (NVIDIA/OpenShell#4195): a restart
	// DefenseClaw makes stops it that way first (QuiesceSandboxes).
	riskReady
	// riskLingering: its MicroVM may run on with what its workload left
	// running, which nothing flushes or stops (MayLinger).
	riskLingering
	// riskActive: it may run work that no flush reaches: starting,
	// provisioning, stopping, or in a phase OpenShell does not name.
	riskActive
)

// restartRiskOf is the restartRisk of sb.
func restartRiskOf(sb *Sandbox) restartRisk {
	switch {
	case sb == nil || !MayHoldCompute(sb.Status.Phase, false):
		return riskNone
	case sb.Status.Phase == PhaseError && !MayLinger(sb.Status.Phase, failureReason(sb)):
		return riskNone
	case MayLinger(sb.Status.Phase, failureReason(sb)):
		return riskLingering
	case sb.Status.Phase == PhaseReady:
		return riskReady
	}
	return riskActive
}

// RestartHolds reports what a restart of sb's gateway, whose compute
// driver's stop keeps what a workload has not synced (stopFlushes: docker)
// or does not (the MicroVM driver, and one DefenseClaw does not know),
// does to sb: holds, it stops or drops work of sb (MayHoldCompute), and
// lingers, sb is a MicroVM that may run on with what its workload left
// running (MayLinger), which a restart DefenseClaw makes refuses until
// its user lets it go (LetGo) or deletes it.
func RestartHolds(sb *Sandbox, stopFlushes bool) (holds, lingers bool) {
	if stopFlushes {
		return sb != nil && MayHoldCompute(sb.Status.Phase, true), false
	}
	r := restartRiskOf(sb)
	return r != riskNone, r == riskLingering
}

// lingerWayOn is what lets a stop of the gateway go ahead under the
// lingering MicroVMs of a refusal.
const lingerWayOn = "nothing in OpenShell flushes or stops a MicroVM whose workload completed or that is in its error state: its VM runs on, " +
	"with whatever its workload left running, until it is deleted or its gateway stops, which would lose what that wrote last. " +
	"`defenseclaw sandbox stop NAME` lets DefenseClaw stop it with the gateway (what is not on its disk yet is lost then), " +
	"and `defenseclaw sandbox delete NAME` deletes it"

// lingering names the sandboxes of list that may linger (riskLingering)
// and that asked does not let go.
func lingering(list []*Sandbox, asked map[string]string) []*Sandbox {
	var out []*Sandbox
	for _, sb := range list {
		if restartRiskOf(sb) == riskLingering && !LetGo(asked, sb) {
			out = append(out, sb)
		}
	}
	return out
}

// phaseNames names each of list as "NAME, phase".
func phaseNames(list []*Sandbox) []string {
	out := make([]string, 0, len(list))
	for _, sb := range list {
		out = append(out, fmt.Sprintf("%s, %s", sb.Name, strings.ToLower(string(sb.Status.Phase))))
	}
	return out
}
