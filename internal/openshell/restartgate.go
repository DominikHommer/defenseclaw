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
	"time"
)

// EndedSettle is how long a MicroVM whose workload ended (WorkloadEnded)
// stays so before a stop of its gateway loses nothing of what the workload
// wrote. Nothing in OpenShell flushes such a MicroVM, in 0.1.3 or 0.1.5:
// it runs a command only in a ready sandbox (ExecSandbox answers "sandbox
// is not ready" in any other phase), its stop returns a completed sandbox,
// or one whose main process failed, as it is, and the flush 0.1.5 makes
// before a stop (NVIDIA/OpenShell#4195) leaves out a sandbox whose main
// process already exited. Its VM keeps running (GAP-0012), and its guest's
// kernel writes back on its own what the workload left unsynced: OpenShell
// boots it on ext4 with Linux's default writeback, which writes a page out
// once it has been dirty for 30 seconds (the flusher wakes every 5 seconds,
// and ext4 commits its journal every 5). Two minutes leave room for a slow
// disk.
const EndedSettle = 2 * time.Minute

// EndedSettleWords is EndedSettle in words.
func EndedSettleWords() string { return fmt.Sprintf("%d minutes", int(EndedSettle/time.Minute)) }

// EndedSettled reports whether a MicroVM seen with its workload ended
// since since has had EndedSettle to write its disk back by now. One not
// known since when (a zero since) has not.
func EndedSettled(since, now time.Time) bool {
	return !since.IsZero() && now.Sub(since) >= EndedSettle
}

// WorkloadEnded reports a phase in which the sandbox's workload no longer
// runs, though its MicroVM may: completed (its main process exited 0), and
// the error state (its main process failed, its VM exited, it never
// started), but for one whose VM process OpenShell's vm driver could not
// poll (said, OpenShell's account of the error state as failureReason or
// a record's PhaseReason gives it, names ProcessPollFailed): its workload
// may still run.
func WorkloadEnded(p SandboxPhase, said string) bool {
	return p == PhaseCompleted || p == PhaseError && !strings.Contains(said, "ProcessPollFailed")
}

// restartRisk is what a restart of a gateway whose compute driver's stop
// keeps only what was flushed (the MicroVM driver, or one DefenseClaw
// does not know) does to one of its sandboxes.
type restartRisk int

const (
	// riskNone: nothing of its workload runs (stopped, deleting, or its
	// provisioning timed out: nothing ran in it since its last stop).
	riskNone restartRisk = iota
	// riskReady: it runs, and sync(1) in it just before the restart keeps
	// what it wrote.
	riskReady
	// riskEnded: its workload ended, and its guest writes back what it
	// wrote within EndedSettle (settleEnded).
	riskEnded
	// riskActive: it may run work that no flush reaches: starting,
	// provisioning, stopping, in a phase OpenShell does not name, or in
	// the error state with its VM process not polled.
	riskActive
)

// restartRiskOf is the restartRisk of sb.
func restartRiskOf(sb *Sandbox) restartRisk {
	switch {
	case sb == nil || !MayHoldCompute(sb.Status.Phase, false):
		return riskNone
	case sb.Status.Phase == PhaseError && ProvisioningTimedOut(failureReason(sb)):
		return riskNone
	case WorkloadEnded(sb.Status.Phase, failureReason(sb)):
		return riskEnded
	case sb.Status.Phase == PhaseReady:
		return riskReady
	}
	return riskActive
}

// RestartHolds reports what a restart of sb's gateway, whose compute
// driver's stop keeps what a workload has not synced (stopFlushes: docker)
// or does not (the MicroVM driver, and one DefenseClaw does not know),
// does to sb: holds, it stops or drops work of sb (MayHoldCompute), and
// ended, sb is a MicroVM whose workload ended, which a restart DefenseClaw
// makes waits for (EndedSettle) instead of flushing it.
func RestartHolds(sb *Sandbox, stopFlushes bool) (holds, ended bool) {
	if stopFlushes {
		return sb != nil && MayHoldCompute(sb.Status.Phase, true), false
	}
	r := restartRiskOf(sb)
	return r != riskNone, r == riskEnded
}

// settleClock is the clock settleEnded waits on.
var settleClock = struct {
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}{time.Now, sleepContext}

// settlePoll is how often settleEnded lists the gateway's sandboxes again.
const settlePoll = 5 * time.Second

// settleEnded waits until every MicroVM of list whose workload ended has
// stayed so for EndedSettle since this wait first saw it in that phase,
// listing the gateway's sandboxes again as it goes, and returns the list
// it saw last: one that left that phase meanwhile (started again, or
// deleted) is judged in its new one by the caller. Nothing tells how long
// a MicroVM has been so before (OpenShell reports no transition time for
// a main process that ended), so the wait counts from now. A list that
// fails, or a context that ends, ends the wait with its error.
func settleEnded(ctx context.Context, c Client, list []*Sandbox) ([]*Sandbox, error) {
	seen := map[string]time.Time{}
	for {
		now := settleClock.now()
		next := map[string]time.Time{}
		wait := time.Duration(0)
		for _, sb := range list {
			if restartRiskOf(sb) != riskEnded {
				continue
			}
			k := sb.Name + "\x00" + string(sb.Status.Phase)
			since, ok := seen[k]
			if !ok {
				since = now
			}
			next[k] = since
			if left := since.Add(EndedSettle).Sub(now); left > wait {
				wait = left
			}
		}
		if wait <= 0 {
			return list, nil
		}
		seen = next
		if err := settleClock.sleep(ctx, min(wait, settlePoll)); err != nil {
			return nil, err
		}
		var err error
		if list, err = c.ListSandboxes(ctx, nil); err != nil {
			return nil, err
		}
	}
}

// phaseNames names each of list as "NAME, phase".
func phaseNames(list []*Sandbox) []string {
	out := make([]string, 0, len(list))
	for _, sb := range list {
		out = append(out, fmt.Sprintf("%s, %s", sb.Name, strings.ToLower(string(sb.Status.Phase))))
	}
	return out
}
