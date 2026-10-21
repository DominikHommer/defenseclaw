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

package manager

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// box is the manager's live state of one sandbox. rec is persisted; the
// rest is rebuilt from OpenShell and the ingress after a restart.
type box struct {
	// op serializes lifecycle operations (create, start, stop, delete,
	// undo) on this sandbox. It is taken before Manager.mu, never under it.
	op sync.Mutex

	// The fields below are guarded by Manager.mu.
	rec record
	sb  *openshell.Sandbox
	eff *packs.Effective
	// decider is the sandbox's own egress proxy decider, built from eff
	// (Manager.egressDecider) whenever eff is.
	decider *egress.Decider
	// policyErr is why the sandbox's policy last failed to resolve, while
	// it fails (Manager.policyUnresolved); eff and decider are nil then.
	policyErr string
	cred      egress.Credential
	phase     audit.SandboxPhase
	creating  bool
	// createCfg is the configuration a managed daemon's create pinned
	// (WithCreateConfig), which the sandbox this create reserved resolves
	// under until the daemon keeps its registration (EndCreate).
	// It binds this box, never its name: a same-name create that fails on
	// the name lends nothing to the sandbox that holds it.
	createCfg *config.Config
	deleted   bool
	orphaned  bool
	missing   bool
	// violations are the clamps and refusals the current configuration
	// applies to the sandbox's run flags, resolved with eff.
	violations []packs.Violation
	// posture is what the feed last heard of the policy the sandbox runs
	// under (announcePosture).
	posture *posture
	// egressOff says why the policy turns the sandbox's web egress off
	// ("" while it is on); egressSynced is set once it was first judged
	// (noteEgressOff).
	egressOff    string
	egressSynced bool
	// unrecorded marks a live sandbox adopted from its labels because the
	// daemon has no readable record of it: the pack, profile and run flags
	// it was created with are unknown, so it fails closed (see
	// errUnrecorded) and its record is never written.
	unrecorded bool
	// retained marks a gone sandbox kept only for its pre-session snapshot
	// (record.Retained, see retire): it has no binding, providers or
	// credential, and only Get, Review, Undo and Delete apply to it.
	retained bool
	// elsewhere says where a sandbox missing from the connected gateway
	// was created, while that is another gateway or workspace
	// (gatewayElsewhere): it is not released then. otherDriver says the
	// gateway is its own but runs another compute driver now.
	elsewhere   string
	otherDriver bool
	started     time.Time

	watchCancel context.CancelFunc
	watchDone   chan struct{}
	// guard is the running nested-repository guard (see guard.go);
	// guardEnding closes once the last one ended, its final pass
	// included.
	guard       *guardRun
	guardEnding chan struct{}
	// observe is the running AI discovery observer of the ready sandbox
	// (discovery.go); discoverMu serializes its discoveries.
	observe    *observeRun
	discoverMu sync.Mutex
	// discoveryReleased is set, under discoverMu, once cleanup removed the
	// sandbox's discovery folder: no discovery writes it again.
	discoveryReleased bool
	// procs is the sandbox's process tree (processes.go), made once its
	// process tree is on.
	procs *procTree
	// findings folds OpenShell's repeats of one finding (foldFinding).
	findings map[string]*findingFold

	hooks hookStats
	// activeAt is the harness's latest activity and activeSince the start
	// of its current run of activity (noteActiveLocked), which the hook
	// silence check measures.
	activeAt    time.Time
	activeSince time.Time
	silentSince time.Time
	// reach is whether the current session's hooks reach the ingress
	// (reach.go); it starts over whenever the sandbox becomes ready.
	reach hookReach
	// tamperStop is set once a hook alarm (a tamper, or silent hooks under
	// hooks.on_silence: stop) scheduled this session's stop.
	tamperStop  bool
	silenceSent bool
	// toolHostsSaid are the harness tool hosts whose refusal the feed
	// explained (firstToolHostRefusal).
	toolHostsSaid map[string]bool
	// seenChunks are the pending draft chunks triage decided; it is pruned
	// to the inbox's pending chunks on every poll.
	seenChunks map[string]struct{}
	// synthetic maps the synthetic addresses OpenShell's policy DNS handed
	// the sandbox to their names (noteSyntheticAddress).
	synthetic map[string]string
	// portLines is what the feed last said this session of each host port
	// other than DefenseClaw's own: reached (true, hostPortAllowed) or
	// closed (false, hostPortDenied).
	portLines map[int]bool
	// proxyOpens are OpenShell's records of the sandbox's connections to
	// the egress proxy, which name the program that opened them, newest
	// last (proxyActor).
	proxyOpens []proxyOpen
	// opens are OpenShell's allowed connections awaiting their first
	// inspected request, by host:port (connectionRequest).
	opens map[string]*openConns
	// triageTimer is a pending draft poll after a denied connection.
	triageTimer *time.Timer
	// triageBusy is set while a triageNow poll runs; triageAgain asks it
	// for one more pass.
	triageBusy, triageAgain bool
	// Proposal flood limits (see approvals.go): recent automatic
	// approvals and recorded rejections, rejections not recorded in the
	// current window, and rules approvals added since the last start.
	autoApproved []time.Time
	rejected     []time.Time
	quietRejects int
	rulesAdded   int

	// triageMu serializes draft polls of this sandbox. It is taken before
	// Manager.mu, never under it.
	triageMu sync.Mutex

	// saveMu serializes writes of rec to disk (saveRecord, removeRecord),
	// so a slower writer never replaces a newer record with an older copy.
	// It is taken before Manager.mu, never under it. dropped, guarded by
	// saveMu, is set once the record file is removed: nothing writes it
	// again.
	saveMu  sync.Mutex
	dropped bool
}

// saveRecord writes the box's record as it is now. Writers change b.rec
// under Manager.mu and then call it; the copy is taken under the box's save
// lock, so concurrent writers leave the newest record on disk. Callers must
// not hold Manager.mu.
func (m *Manager) saveRecord(b *box) error {
	b.saveMu.Lock()
	defer b.saveMu.Unlock()
	if b.dropped {
		return nil
	}
	m.mu.Lock()
	rec, unrecorded := b.rec, b.unrecorded
	m.mu.Unlock()
	if unrecorded {
		// Its labels are all there is: writing them as its record would
		// make the next restart run it under the default policy.
		return nil
	}
	return m.records.save(&rec)
}

// removeRecord deletes the box's record file for good: later saves of the
// box are dropped, so a writer that raced the removal cannot bring the
// record of a deleted sandbox back. Callers must not hold Manager.mu.
func (m *Manager) removeRecord(b *box) error {
	b.saveMu.Lock()
	defer b.saveMu.Unlock()
	b.dropped = true
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	return m.records.remove(name)
}

type hookStats struct {
	lastHook    time.Time
	lastOTLP    time.Time
	lastNotify  time.Time
	requests    int64
	toolCalls   int64
	toolBlocked int64
	toolAsked   int64
	lastBlocked string
	// events counts the verdicts per hook event name (hookLabel of the
	// harness's name), at most sandboxapi.MaxHookEvents names; otherEvents
	// counts the rest (countEvent).
	events      map[string]int64
	otherEvents int64
	// promptBlocked counts the prompts DefenseClaw blocked.
	promptBlocked int64
	// tampered counts tool calls that ran without a DefenseClaw verdict.
	tampered   int64
	lastTamper time.Time
	// ingressRefused counts the ingress connections and requests OpenShell
	// refused.
	ingressRefused     int64
	lastIngressRefused time.Time
	// refusedByMapping is set when the last refusal was a transparent
	// mapping denial nothing answered (confirmMappingDenialLocked).
	refusedByMapping bool
	// failed counts the hook posts the ingress answered with an error;
	// lastFailure says how the last one was answered. failureNoticeAt is
	// when the feed last reported failures, unnoticed how many came since.
	failed          int64
	lastFailure     string
	lastFailureAt   time.Time
	failureNoticeAt time.Time
	unnoticed       int64
	// failureCause and answeredAt are what the status says of the last
	// failure (sandboxapi.HookCoverage.LastHookFailureCause,
	// HooksAnsweredAt; notePlaceholderFailureLocked, noteHookAnsweredLocked).
	failureCause string
	answeredAt   time.Time
	// modelRejected says the model API rejected the sandbox's model
	// credential, and how to hand it a fresh one; modelRejectedAt is the
	// last rejection (observeModelAnswerLocked).
	modelRejected   string
	modelRejectedAt time.Time
	// placeholderAt is when OpenShell last refused a request whose body
	// carried a credential placeholder (notePlaceholderLocked).
	placeholderAt time.Time
}

// hookCounts are the hook counters a sandbox's record keeps (keepHookCounts),
// so a restarted daemon goes on from them as it does from the kept
// destinations: sandbox status and the Sandboxes list keep the counts of the
// sandbox's life (GAP-0156). It keeps the verdict on the last session's
// hooks too (unreachable, silent), so a stopped sandbox says the same of
// its session after a restart (GAP-0186); a session that starts, and so a
// running sandbox a restarted daemon adopts, is judged afresh (lifecycle).
// The other times and the notices start over with the daemon.
type hookCounts struct {
	Requests       int64            `json:"requests,omitempty"`
	ToolCalls      int64            `json:"tool_calls,omitempty"`
	ToolBlocked    int64            `json:"tool_blocked,omitempty"`
	ToolAsked      int64            `json:"tool_asked,omitempty"`
	PromptBlocked  int64            `json:"prompt_blocked,omitempty"`
	LastBlocked    string           `json:"last_blocked,omitempty"`
	Events         map[string]int64 `json:"events,omitempty"`
	OtherEvents    int64            `json:"other_events,omitempty"`
	Tampered       int64            `json:"tampered,omitempty"`
	Failed         int64            `json:"failed,omitempty"`
	IngressRefused int64            `json:"ingress_refused,omitempty"`
	// UnreachableSince, UnreachableReason and NoHookYet are the session's
	// reach verdict (hookReach), SilentSince when its hooks fell silent.
	UnreachableSince  time.Time `json:"unreachable_since,omitzero"`
	UnreachableReason string    `json:"unreachable_reason,omitempty"`
	NoHookYet         bool      `json:"no_hook_yet,omitempty"`
	SilentSince       time.Time `json:"silent_since,omitzero"`
}

// counts are the counters of h a record keeps.
func (h *hookStats) counts() hookCounts {
	return hookCounts{
		Requests: h.requests, ToolCalls: h.toolCalls, ToolBlocked: h.toolBlocked, ToolAsked: h.toolAsked,
		PromptBlocked: h.promptBlocked, LastBlocked: h.lastBlocked, Events: maps.Clone(h.events), OtherEvents: h.otherEvents,
		Tampered: h.tampered, Failed: h.failed, IngressRefused: h.ingressRefused,
	}
}

// restore starts h from the counters a record kept, with at most
// sandboxapi.MaxHookEvents event names (countEvent).
func (h *hookStats) restore(c *hookCounts) {
	if c == nil {
		return
	}
	h.requests, h.toolCalls, h.toolBlocked, h.toolAsked = c.Requests, c.ToolCalls, c.ToolBlocked, c.ToolAsked
	h.promptBlocked, h.lastBlocked, h.otherEvents = c.PromptBlocked, c.LastBlocked, c.OtherEvents
	h.tampered, h.failed, h.ingressRefused = c.Tampered, c.Failed, c.IngressRefused
	for name, n := range c.Events {
		if len(h.events) >= sandboxapi.MaxHookEvents {
			h.otherEvents += n
			continue
		}
		if h.events == nil {
			h.events = make(map[string]int64)
		}
		h.events[name] = n
	}
}

// noteHookCountsLocked puts the box's hook counters and its session's hook
// verdict in its record and reports whether they moved since the record
// last kept them. Callers hold Manager.mu.
func (b *box) noteHookCountsLocked() bool {
	c := b.hooks.counts()
	c.UnreachableSince, c.UnreachableReason, c.NoHookYet = b.reach.since, b.reach.reason, b.reach.noHookYet
	c.SilentSince = b.silentSince
	kept := b.rec.HookCounts
	if kept == nil {
		kept = &hookCounts{}
	}
	if reflect.DeepEqual(*kept, c) {
		return false
	}
	b.rec.HookCounts = &c
	return true
}

// keepHookCounts writes the record of every sandbox whose hook counters
// moved since its record last kept them. It runs with the destinations
// flush and when the daemon stops, so a daemon that did not stop cleanly
// loses at most the last interval's counts. Callers must not hold
// Manager.mu.
func (m *Manager) keepHookCounts() {
	m.mu.Lock()
	var moved []*box
	var names []string
	for name, b := range m.boxes {
		if !b.deleted && !b.retained && !b.creating && b.noteHookCountsLocked() {
			moved, names = append(moved, b), append(names, name)
		}
	}
	m.mu.Unlock()
	for i, b := range moved {
		if err := m.saveRecord(b); err != nil {
			m.logf("keep the hook counts of %s: %v", names[i], err)
		}
	}
}

var imageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// identity is the correlation.sandbox group for the box. Callers hold
// Manager.mu.
func (b *box) identity() audit.SandboxIdentity {
	id := audit.SandboxIdentity{
		ID: b.rec.ID, Name: b.rec.Name, Connector: b.rec.Harness, Runtime: audit.SandboxRuntimeOpenShell,
		Profile: b.rec.Profile, Pack: b.rec.Pack, Phase: b.phase, WorkdirMode: b.rec.WorkdirMode,
		BindingID: b.rec.BindingID,
	}
	// Telemetry names the driver as OpenShell does (audit.SandboxDriverVM is
	// "vm"); one this build does not know is left out, not guessed.
	if d, ok := openshell.LookupDriver(b.rec.Driver); ok {
		id.Driver = string(d.Name)
		id.DriverReason = b.rec.DriverReason
	}
	// The image that runs: the run image when the driver runs one.
	digest := b.rec.ImageID
	if b.rec.RunImageID != "" {
		digest = b.rec.RunImageID
	}
	if imageDigestPattern.MatchString(digest) {
		id.ImageDigest = digest
	}
	if b.sb != nil {
		id.PolicyVersion = b.sb.Status.CurrentPolicyVersion
	}
	return id
}

// auditPhase maps an OpenShell phase onto the telemetry vocabulary.
func auditPhase(p openshell.SandboxPhase) audit.SandboxPhase {
	switch p {
	case openshell.PhaseProvisioning:
		return audit.SandboxPhaseProvisioning
	case openshell.PhaseStarting:
		return audit.SandboxPhaseStarting
	case openshell.PhaseReady:
		return audit.SandboxPhaseReady
	case openshell.PhaseStopping:
		return audit.SandboxPhaseStopping
	case openshell.PhaseStopped:
		return audit.SandboxPhaseStopped
	case openshell.PhaseCompleted:
		return audit.SandboxPhaseCompleted
	case openshell.PhaseError:
		return audit.SandboxPhaseError
	case openshell.PhaseDeleting:
		return audit.SandboxPhaseDeleting
	default:
		return audit.SandboxPhaseUnknown
	}
}

// lifecycle records a phase transition (and the matching feed event) unless
// the box is already in phase and force is unset. Callers must not hold
// Manager.mu.
func (m *Manager) lifecycle(ctx context.Context, b *box, phase audit.SandboxPhase, trigger audit.SandboxLifecycleTrigger,
	force bool, cond *audit.SandboxCondition, exit *int32) {
	release := m.gatewayRelease()
	m.mu.Lock()
	if b.phase == phase && !force {
		m.mu.Unlock()
		return
	}
	// A daemon that loads the box sees its phase for the first time too.
	seen := b.phase != phase
	previous := b.phase
	if previous == "" && b.rec.Phase != "" {
		previous = audit.SandboxPhase(b.rec.Phase)
	}
	// A MicroVM that left the ready phase without DefenseClaw stopping or
	// deleting it (whose own transitions come first) went down without a
	// flush: the OpenShell gateway restarted under it, for one (GAP-0289).
	driver, known := openshell.LookupDriver(b.rec.Driver)
	unflushed := known && !driver.StopFlushes && trigger == audit.SandboxTriggerWatch && previous == audit.SandboxPhaseReady &&
		(phase == audit.SandboxPhaseProvisioning || phase == audit.SandboxPhaseStarting || phase == audit.SandboxPhaseStopped || phase == audit.SandboxPhaseError)
	if unflushed {
		// The status and the pull's review say so after the feed has
		// scrolled past it (GAP-0367).
		b.rec.UnflushedAt = m.now().UTC()
	}
	b.phase = phase
	if phase == audit.SandboxPhaseReady && (previous != audit.SandboxPhaseReady || b.started.IsZero()) {
		b.started = m.now()
		b.reach = hookReach{}
		// The silence check starts over with the session: one that stopped
		// a session for silent hooks stops the next one too while they stay
		// silent.
		b.silentSince, b.silenceSent = time.Time{}, false
		b.portLines, b.opens = nil, nil
		// The new session's hooks name its session.
		m.tel.forgetSandbox(b.rec.Name)
		if previous != audit.SandboxPhaseReady {
			b.rec.Sessions++
			// The session runs the supervisor of the gateway it started on
			// (unknown while no gateway is connected: the last one's).
			if release != "" {
				b.rec.SessionRelease = release
			}
		}
		// A restarted daemon that finds the sandbox still ready keeps the
		// time it became ready (uptime); a real transition takes now.
		if previous != audit.SandboxPhaseReady || b.rec.ReadyAt.IsZero() {
			b.rec.ReadyAt = b.started.UTC()
			// The session's harness launches with the skip-permissions
			// mode the policy allows now; a later change applies from the
			// next start (launchYolo).
			yolo := launchYolo(b)
			b.rec.SessionYolo = &yolo
		}
	}
	if phase != audit.SandboxPhaseReady {
		b.rec.ReadyAt = time.Time{}
		b.rec.SessionYolo = nil
	}
	b.rec.Phase = string(phase)
	// A republished error phase (a restarted daemon's reconcile) says
	// nothing new of why: the record's reason stays.
	if phase != audit.SandboxPhaseError || cond != nil || previous != phase {
		b.rec.PhaseReason = ""
	}
	if retainedPhase(phase) {
		// A record from before the field (a restarted daemon's) counts
		// from now: never longer than the floor allows from when it is seen.
		if b.rec.StoppedAt.IsZero() || !retainedPhase(previous) {
			b.rec.StoppedAt = m.now().UTC()
		}
	} else {
		b.rec.StoppedAt = time.Time{}
	}
	if phase == audit.SandboxPhaseError && (cond != nil || previous != phase) {
		b.rec.PhaseReason = errorPhaseReason(cond)
	}
	// A MicroVM whose workload ended keeps what it wrote once its guest has
	// written its disk back (openshell.EndedSettle), counted from when this
	// daemon saw it so: one that loads the box, which cannot tell what
	// happened while it was down, counts from now.
	if workloadEnded(phase, b.rec.PhaseReason) {
		if seen || b.rec.EndedAt.IsZero() {
			b.rec.EndedAt = m.now().UTC()
		}
	} else {
		b.rec.EndedAt = time.Time{}
	}
	// The record written below keeps the hook counts reached so far.
	b.noteHookCountsLocked()
	id := b.identity()
	rec := b.rec
	m.mu.Unlock()
	// A restarted daemon republishes the phase its record held: telemetry
	// records it again, but nothing happened, so the feed gets no line
	// ("sandbox X stopped" for every stopped sandbox at a restart, GAP-0167).
	unchanged := previous == phase
	if unchanged {
		previous = ""
	}
	ev := audit.SandboxLifecycleEvent{
		Sandbox: id, PreviousPhase: previous, Trigger: trigger, ExitCode: exit, Condition: cond, Timestamp: m.now(),
		UserID: strconv.Itoa(m.host.UID), UserName: m.host.Name,
	}
	m.tel.RecordSandboxLifecycle(ctx, ev)
	if phase != audit.SandboxPhaseDeleted {
		if err := m.saveRecord(b); err != nil {
			m.logf("save the record of %s: %v", rec.Name, err)
		}
	}
	if phase == audit.SandboxPhaseStopped || phase == audit.SandboxPhaseCompleted || phase == audit.SandboxPhaseError {
		// The session is over: keep what it reached.
		m.flushDestinations(rec.Name)
	}
	if !unchanged {
		msg := lifecycleMessage(rec.Name, phase)
		if phase == audit.SandboxPhaseError {
			// Why, and the way on (GAP-0278).
			if rec.PhaseReason != "" {
				msg += " (" + rec.PhaseReason + ")"
			}
			msg += "; " + errorPhaseWayOn(rec.Name, rec.PhaseReason, m.upgradeWayOn(release), stopLosesWrites(rec.Driver))
		}
		m.feed.Publish(sandboxapi.ActivityEvent{
			Kind: sandboxapi.ActivityLifecycle, Sandbox: rec.Name, Phase: string(phase), Reason: string(trigger),
			Message: msg,
		})
	}
	if unflushed {
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: rec.Name, Severity: "MEDIUM",
			Reason: sandboxapi.ReasonUnflushedStop, Message: unflushedStopMessage(rec.Name)})
	}
	if phase == audit.SandboxPhaseReady && !openshell.RunsSandboxes(rec.SessionRelease) {
		// Once a session, and again for a restarted daemon that finds it
		// still running.
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: rec.Name, Severity: "HIGH",
			Reason: sandboxapi.ReasonOldSupervisor, Message: oldSupervisorMessage(rec.Name, rec.SessionRelease, m.upgradeWayOn(release))})
	}
	m.syncGuard(b, phase)
	m.syncObserve(b, phase)
}

// MayHoldCompute reports whether a sandbox in phase (sandboxapi's, as
// audit.SandboxPhase spells it, or a view's missing) on the compute driver
// driver (a record's: "" is docker) may hold compute that stopping its
// OpenShell gateway would end without the flush a DefenseClaw stop does
// first, or half started (openshell.MayHoldCompute): every phase but
// stopped, deleting, deleted and missing (OpenShell no longer has the
// sandbox), an unknown or empty one included, except that a sandbox whose
// workload ended (completed, or OpenShell's error state) holds none on a
// driver whose own stop keeps the workload's writes (docker: a container
// that exited). A MicroVM keeps running after its workload completes or
// fails, until it is deleted or its gateway stops (GAP-0012), and nothing
// in OpenShell flushes it (openshell.EndedSettle), so whatever stops the
// gateway on its own (a managed setup switch, the daemon's idle stop of
// the gateway, an upgrade) waits for it: HoldsCompute says until when.
func MayHoldCompute(phase, driver string) bool {
	switch audit.SandboxPhase(phase) {
	case audit.SandboxPhaseStopped, audit.SandboxPhaseDeleting, audit.SandboxPhaseDeleted, phaseMissing:
		return false
	case audit.SandboxPhaseCompleted, audit.SandboxPhaseError:
		return stopLosesWrites(driver)
	}
	return true
}

// phaseMissing is the phase of the view of a sandbox OpenShell no longer
// has, whose state DefenseClaw still holds.
const phaseMissing audit.SandboxPhase = "missing"

// HoldsCompute is MayHoldCompute for the sandbox v as the manager reports
// it, at now: a MicroVM whose workload ended (workloadEnded) holds nothing
// a stop of its gateway would lose once its guest has had
// openshell.EndedSettle since v.EndedAt to write its disk back, and
// nothing once OpenShell gave up provisioning it, since nothing ran in it
// after its last stop. What stops the gateway on its own waits for the
// others.
func HoldsCompute(v sandboxapi.Sandbox, now time.Time) bool {
	return holdsCompute(audit.SandboxPhase(v.Phase), v.Driver, v.PhaseReason, v.EndedAt, now)
}

// holdsCompute is HoldsCompute on a sandbox's phase, driver, error-phase
// reason and EndedAt.
func holdsCompute(phase audit.SandboxPhase, driver, reason string, endedAt, now time.Time) bool {
	switch {
	case !MayHoldCompute(string(phase), driver):
		return false
	case phase == audit.SandboxPhaseError && openshell.ProvisioningTimedOut(reason):
		return false
	case workloadEnded(phase, reason):
		return !openshell.EndedSettled(endedAt, now)
	}
	return true
}

// workloadEnded is openshell.WorkloadEnded on a sandbox's phase and
// error-phase reason (the record's PhaseReason).
func workloadEnded(phase audit.SandboxPhase, reason string) bool {
	return phase == audit.SandboxPhaseCompleted || phase == audit.SandboxPhaseError && openshell.WorkloadEnded(openshell.PhaseError, reason)
}

// stopLosesWrites reports a compute driver (a record's: "" is docker) whose
// stop does not keep what the workload has not synced: the MicroVM driver,
// and one this build does not know.
func stopLosesWrites(driver string) bool {
	d, ok := openshell.LookupDriver(driver)
	return !ok || !d.StopFlushes
}

// errorPhaseWayOn is what to do about a sandbox in OpenShell's error phase:
// its container stopped (a Docker restart stops every one), its workload
// failed, or OpenShell gave up provisioning it. A gateway that runs
// sandboxes (openshell.SandboxMin and later) stops a sandbox in that phase
// and starts it again after (NVIDIA/OpenShell#4231), which keeps the
// sandbox and its work, except after a provisioning timeout: OpenShell
// refuses that stop while its own cleanup reclaims what the attempt started,
// and a start after the cleanup provisions the sandbox again. An older
// gateway can neither stop nor start it: upgrade (upgradeWayOn, "" on a
// gateway that runs sandboxes) is how OpenShell is upgraded first, and the
// way on after it is the one of the upgraded gateway, which for a
// provisioning timeout is still the start with no stop. On a MicroVM
// (microVM) the upgrade waits for it, since nothing in OpenShell flushes
// it: until its guest has written its disk back (openshell.EndedSettle),
// which keeps its work, or, while OpenShell cannot tell whether its
// workload still runs, until it is deleted.
func errorPhaseWayOn(name, reason, upgrade string, microVM bool) string {
	switch {
	case reason == overlayDiskFullText:
		return overlayDiskWayOn(name)
	case upgrade != "" && openshell.ProvisioningTimedOut(reason):
		return "this OpenShell can neither stop nor start a sandbox in its error state: " + upgrade + ", then wait a minute for OpenShell's cleanup of " +
			"the provisioning that timed out and `defenseclaw sandbox start " + name + "` (no stop: OpenShell " + openshell.SandboxMin +
			" refuses to stop a sandbox whose provisioning timed out), which provisions it again"
	case upgrade != "" && microVM && !openshell.WorkloadEnded(openshell.PhaseError, reason):
		return "this OpenShell can neither stop nor start a sandbox in its error state, and OpenShell could not tell whether its MicroVM still runs its workload, " +
			"so the upgrade waits for it: `defenseclaw sandbox delete " + name + "` ends that wait if its work is not needed; otherwise, once it has left " +
			"that state, " + upgrade
	case upgrade != "" && microVM:
		return "this OpenShell can neither stop nor start a sandbox in its error state, and nothing flushes its MicroVM, whose guest writes its disk back " +
			"on its own within " + openshell.EndedSettleWords() + " of its workload's end: the upgrade waits for that, and so keeps its work. " + upgrade +
			", then `defenseclaw sandbox stop " + name + "` and `defenseclaw sandbox start " + name + "`, which keep the sandbox and its work"
	case upgrade != "":
		return "this OpenShell can neither stop nor start a sandbox in its error state: " + upgrade + ", then `defenseclaw sandbox stop " + name +
			"` and `defenseclaw sandbox start " + name + "`, which keep the sandbox and its work"
	case openshell.ProvisioningTimedOut(reason):
		return "OpenShell gave up provisioning it and refuses to stop it while its own cleanup reclaims what it started: wait a minute, then `defenseclaw sandbox start " +
			name + "` (no stop), which provisions it again; a start that says the cleanup is still pending is tried again a little later"
	}
	return "fix what stopped it (start Docker again, for one), then `defenseclaw sandbox stop " + name +
		"` and `defenseclaw sandbox start " + name + "`, which keep the sandbox and its work"
}

// upgradeWayOn is how this host's OpenShell is upgraded when the gateway
// release (as its health reported it) runs no sandbox work
// (openshell.SandboxMin), "" when it does or no gateway answered. On a
// managed computer the release is the administrator's.
func (m *Manager) upgradeWayOn(release string) string {
	v, err := openshell.ParseVersion(release)
	if err != nil || openshell.CheckSandboxRelease(v) == nil {
		return ""
	}
	if m.managedMode() {
		return "on this managed computer the OpenShell release is your administrator's (enterprise.openshell.version): ask IT for " +
			openshell.InstallerVersion + " or later; where DefenseClaw installs OpenShell for you, your gateway moves to it once none of your sandboxes runs " +
			"(`defenseclaw sandbox stop NAME` flushes and stops one) and every MicroVM whose workload ended has had " + openshell.EndedSettleWords() +
			" to write its disk back, which keeps its work"
	}
	return "upgrade OpenShell " + v.String() + " to " + openshell.InstallerVersion + " in place with `defenseclaw sandbox setup --install-openshell`"
}

// sandboxReleaseRefusal refuses sandbox work (a create, a start) on a
// gateway older than openshell.SandboxMin.
func (m *Manager) sandboxReleaseRefusal(gw *Gateway) error {
	v, err := openshell.ParseVersion(gw.Version)
	if err != nil {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the OpenShell gateway reported an unrecognized release %q, so DefenseClaw runs no sandbox on it", gw.Version)
	}
	if err := openshell.CheckSandboxRelease(v); err != nil {
		return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: err.Error(), Detail: m.upgradeWayOn(gw.Version)}
	}
	return nil
}

// oldSupervisorWarning is the sandbox's warning while its session runs the
// supervisor of an OpenShell release older than openshell.SandboxMin
// (oldSupervisorMessage).
const oldSupervisorWarning = "this session may run the supervisor of an OpenShell older than " + openshell.SandboxMin +
	", whose network broker can let the sandbox's connections bypass its policy (NVIDIA/OpenShell#4494): " +
	"stop and start the sandbox on OpenShell " + openshell.SandboxMin + " or later"

// oldSupervisorMessage is the feed's warning about the sandbox name whose
// session started on OpenShell release (a record from before DefenseClaw
// kept it: ""), older than openshell.SandboxMin: it runs that release's
// supervisor until it stops, whatever the gateway runs now.
func oldSupervisorMessage(name, release, upgrade string) string {
	msg := "⚠ " + name + "'s session started on OpenShell " + release + ", whose network broker can let the sandbox's connections bypass its policy " +
		"(NVIDIA/OpenShell#4494), and it keeps that supervisor while it runs: "
	if release == "" {
		msg = "⚠ " + name + "'s session started before DefenseClaw kept the OpenShell release a session starts on, so it may run a supervisor older than " +
			openshell.SandboxMin + ", whose network broker can let the sandbox's connections bypass its policy (NVIDIA/OpenShell#4494): "
	}
	if upgrade != "" {
		return msg + "stop it (`defenseclaw sandbox stop " + name + "`), " + upgrade + ", then start it"
	}
	return msg + "`defenseclaw sandbox stop " + name + "` and `defenseclaw sandbox start " + name + "` restart it on this gateway's supervisor"
}

// unflushedStopMessage is the feed's warning about the MicroVM name that
// went down without DefenseClaw stopping it.
func unflushedStopMessage(name string) string {
	return "⚠ " + name + "'s MicroVM went down without DefenseClaw stopping it (the OpenShell gateway restarted, for one), so what it wrote " +
		"in its last seconds may be missing or end in zero bytes: check those files before you bring the work back (its review flags the ones " +
		"that end in zero bytes). `defenseclaw sandbox stop` flushes first, and so do DefenseClaw's own gateway restarts"
}

// errorPhaseReason is why a sandbox is in OpenShell's error phase, in
// words: its full MicroVM disk, or what its conditions say (cut at 200
// characters).
func errorPhaseReason(cond *audit.SandboxCondition) string {
	if cond == nil {
		return ""
	}
	said := strings.TrimSpace(strings.Trim(strings.TrimSpace(cond.Reason)+": "+strings.TrimSpace(cond.Message), ": "))
	if overlayDiskFull(said) {
		return overlayDiskFullText
	}
	return truncate(sandboxapi.DisplayText(said), 200)
}

// overlayDiskFullText is why a MicroVM whose own disk is full does not
// start. OpenShell's error is the guest console: "setting up writable
// overlay root ... touch: cannot touch '/newroot/etc/passwd': Read-only
// file system" (GAP-0297).
const overlayDiskFullText = "its own disk is full: the MicroVM writes its changes to an overlay disk of its own, and could not set up its root on it"

// overlayDiskFull reports whether OpenShell's account of a failed start
// (an error, a condition) is a MicroVM's overlay disk that has no room
// left: the guest could not write its root on it.
func overlayDiskFull(said string) bool {
	return strings.Contains(said, "writable overlay root") &&
		(strings.Contains(said, "Read-only file system") || strings.Contains(said, "No space left on device"))
}

// overlayDiskWayOn is what to do about the MicroVM name whose own disk is
// full: OpenShell cannot start it again, so its work cannot be read.
func overlayDiskWayOn(name string) string {
	return "a MicroVM stopped with its disk full cannot start again, so its work that was not pulled cannot be read any more: " +
		"`defenseclaw sandbox delete " + name + "`, then run again; overlay_disk_mib under [openshell.drivers.vm] in the gateway's gateway.toml " +
		"sizes the disk of new sandboxes (`defenseclaw sandbox doctor` shows it). Free space in a running MicroVM before it stops " +
		"(`defenseclaw sandbox exec <name> -- df -h /`)"
}

// overlayDiskRefusal is a start that failed because the MicroVM's own
// disk is full, as people read it, or nil (the guest console OpenShell
// returns is no message for them).
func overlayDiskRefusal(name string, err error) error {
	if err == nil || !overlayDiskFull(err.Error()) {
		return nil
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeConflict, Message: name + " cannot start: " + overlayDiskFullText, Detail: overlayDiskWayOn(name)}
}

// errorPhaseRefusal is OpenShell's refusal to stop or start the sandbox
// name in its error phase as people read it ("Conflict: sandbox must be
// Stopped, Completed, or a failed main-process Error to start", or the
// refusals after a provisioning timeout), or nil.
func (m *Manager) errorPhaseRefusal(name, reason, driver string, err error) error {
	switch {
	case err == nil:
		return nil
	case openshell.ProvisioningTimedOut(err.Error()):
		if !openshell.ProvisioningTimedOut(reason) {
			reason = "sandbox provisioning timed out"
		}
	case !openshell.IsConflict(err) || !strings.Contains(err.Error(), "current phase: Error"):
		return nil
	}
	return errorPhaseError(name, reason, m.upgradeWayOn(m.gatewayRelease()), stopLosesWrites(driver))
}

// errorPhaseNow is errorPhaseRefusal for an operation whose error does not
// say why (the gateway connection closed under it, as a Docker restart
// makes it): b's phase as OpenShell reported it after the failure
// (restorePhase); nil unless that is the error phase (GAP-0337).
func (m *Manager) errorPhaseNow(b *box) error {
	m.mu.Lock()
	name, reason, driver := b.rec.Name, b.rec.PhaseReason, b.rec.Driver
	inError := b.sb != nil && auditPhase(b.sb.Status.Phase) == audit.SandboxPhaseError
	m.mu.Unlock()
	if !inError {
		return nil
	}
	return errorPhaseError(name, reason, m.upgradeWayOn(m.gatewayRelease()), stopLosesWrites(driver))
}

// connectionClosed reports a call that failed because the client's
// connection to the OpenShell gateway closed under it (gRPC's "the client
// connection is closing"), which says nothing to the user.
func connectionClosed(err error) bool {
	return err != nil && strings.Contains(err.Error(), "client connection is closing")
}

// errorPhaseError explains name's error phase, with the way on.
func errorPhaseError(name, reason, upgrade string, microVM bool) error {
	msg := name + " is in OpenShell's error state"
	if reason != "" {
		msg += ": " + reason
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeConflict, Message: msg, Detail: errorPhaseWayOn(name, reason, upgrade, microVM)}
}

func lifecycleMessage(name string, phase audit.SandboxPhase) string {
	switch phase {
	case audit.SandboxPhaseCreating:
		return "creating sandbox " + name
	case audit.SandboxPhaseReady:
		return "sandbox " + name + " is ready"
	case audit.SandboxPhaseStopped:
		return "sandbox " + name + " stopped"
	case audit.SandboxPhaseDeleted:
		return "sandbox " + name + " deleted"
	case audit.SandboxPhaseError:
		return "sandbox " + name + " failed"
	default:
		return "sandbox " + name + " is " + string(phase)
	}
}

// displaySafe makes the text of a view that a sandbox or its project can
// shape (warnings naming project files, OpenShell's endpoint reports, the
// last blocked tool, the workspace summary) safe to print on the user's
// terminal. The nested-repository paths are cleaned by nestedView.
func displaySafe(v *sandboxapi.Sandbox) {
	v.Warnings = sandboxapi.DisplayTexts(v.Warnings)
	v.Hooks.LastBlocked = sandboxapi.DisplayText(v.Hooks.LastBlocked)
	for i := range v.Endpoints {
		ep := &v.Endpoints[i]
		ep.Host, ep.Path, ep.Result = sandboxapi.DisplayText(ep.Host), sandboxapi.DisplayText(ep.Path), sandboxapi.DisplayText(ep.Result)
	}
	if w := v.Workspace; w != nil {
		clean := *w
		clean.Project = sandboxapi.DisplayText(w.Project)
		clean.Hidden, clean.Protected = sandboxapi.DisplayTexts(w.Hidden), sandboxapi.DisplayTexts(w.Protected)
		clean.Context, clean.Warnings = sandboxapi.DisplayTexts(w.Context), sandboxapi.DisplayTexts(w.Warnings)
		v.Workspace = &clean
	}
}

// postureDrift explains how the policy a sandbox runs under now (eff)
// differs from the one it was created with (rec): the configuration
// changed since, an administrator's required pack or minimum profile, say.
// A live mount the policy now wants as a copy cannot become one; it keeps
// running until the sandbox stops, and checkStart refuses the next start.
func postureDrift(rec record, eff *packs.Effective) []string {
	var out []string
	pack := ""
	if eff.Pack != nil {
		pack = eff.Pack.Name
	}
	if (rec.Pack != "" && pack != rec.Pack) || (rec.Profile != "" && eff.Profile != rec.Profile) ||
		(rec.NetworkMode != "" && eff.NetworkMode != rec.NetworkMode) || (rec.Approvals != "" && eff.Approvals != rec.Approvals) {
		out = append(out, fmt.Sprintf("the sandbox policy changed since this sandbox was created (pack %s, profile %s, network %s, approvals %s); "+
			"it now runs under pack %s, profile %s, network %s, approvals %s",
			firstNonEmpty(rec.Pack, "-"), firstNonEmpty(rec.Profile, "-"), firstNonEmpty(rec.NetworkMode, "-"), firstNonEmpty(rec.Approvals, "-"),
			firstNonEmpty(pack, "-"), eff.Profile, eff.NetworkMode, eff.Approvals))
	}
	// The harness run files follow the policy from the next start on
	// (refreshRunConfig); the running session keeps what it started with.
	if rec.RunConfig != nil && !rec.RunConfig.Safe && (!(rec.Yolo) || !(eff.Yolo)) {
		out = append(out, "the sandbox policy no longer lets the harness skip its permission prompts; "+
			"this session keeps skip-permissions mode until the sandbox stops, and its next start keeps the prompts")
	}
	if rec.MCP != nil && rec.MCP.ProjectServers == packs.MCPProjectServersAllow && eff.MCP.ProjectServers != packs.MCPProjectServersAllow {
		out = append(out, "the sandbox policy now blocks the project's own MCP servers; this session may still start them until the sandbox stops")
	}
	if rec.MCP != nil && len(rec.MCP.Imported) > 0 && !eff.MCP.Import {
		out = append(out, "the sandbox policy no longer brings your MCP servers into sandboxes; this session keeps them until the sandbox stops")
	}
	if rec.WorkdirMode == config.OpenShellWorkdirMount && eff.Workspace.Mode != config.OpenShellWorkdirMount {
		out = append(out, "the sandbox policy now works on a copy of this project, but this sandbox mounts it live; "+
			"the mount stays until the sandbox stops, and it cannot start again: delete it and run it again")
	}
	return out
}

// sessionDrift explains how the session running now breaks the policy the
// sandbox would start under today (eff): it keeps what it was launched
// with until it ends, so an administrator checking compliance sees which
// sessions still run out of policy. sessionYolo is the session's
// skip-permissions mode, nextYolo the next launch's.
func sessionDrift(rec record, eff *packs.Effective, sessionYolo, nextYolo bool) []string {
	var out []string
	if sessionYolo && !nextYolo {
		why := "the sandbox policy now keeps the harness's permission prompts"
		var v *packs.Violation
		if err := eff.Allow(packs.Action{Kind: packs.ActionYolo}); errors.As(err, &v) && v.Admin() {
			why = "your organization disabled it (" + v.Constraint + ")"
		}
		out = append(out, "skip-permissions stays on in the session running now, which began before "+why+
			"; the harness keeps its permission prompts from the next start")
	}
	if err := eff.Allow(packActionHarness(rec.Harness)); err != nil {
		out = append(out, "the session running now uses a harness the sandbox policy no longer allows ("+err.Error()+
			"); it keeps running until it ends, and the sandbox cannot start again")
	}
	return out
}

// viewOf renders the API form of a box.
func (m *Manager) viewOf(b *box) sandboxapi.Sandbox {
	m.mu.Lock()
	v := m.view(b)
	proxy := m.proxy
	bindingID := b.rec.BindingID
	shared := sharedLimitsOf(b)
	accepted := b.rec.Accepted
	m.mu.Unlock()
	m.decorate(&v, proxy, bindingID, accepted)
	views := []sandboxapi.Sandbox{v}
	m.sharedLimitsWarnings(views, []openshell.ComputeDriver{shared})
	return views[0]
}

// sharedLimitsOf is the driver of a box judged by the cpu and memory
// every sandbox of it gets (a driver without per-sandbox limits); ""
// for the others and for a deleted one. Callers hold Manager.mu.
func sharedLimitsOf(b *box) openshell.ComputeDriver {
	if d, _ := openshell.LookupDriver(b.rec.Driver); !d.SandboxLimits && !b.retained {
		return d.Name
	}
	return ""
}

// sharedLimitsWarnings warns on each view whose driver (drivers[i]) has
// no per-sandbox limits when the cpu and memory every sandbox of it gets
// now exceed the max_resources of the sandbox's own floor
// (Effective.MaxResources): the start judges those values (checkStart),
// not what the record kept at create, and a new sandbox would get them
// too, so the fix is to lower them. Callers must not hold Manager.mu (the
// values are read from the gateway's configuration).
func (m *Manager) sharedLimitsWarnings(views []sandboxapi.Sandbox, drivers []openshell.ComputeDriver) {
	type limit struct {
		driver openshell.ComputeDriver
		max    config.OpenShellResourcesConfig
	}
	warnings := map[limit]string{}
	for i := range views {
		name := drivers[i]
		if name == "" {
			continue
		}
		m.mu.Lock()
		var eff *packs.Effective
		if b := m.boxes[views[i].Name]; b != nil {
			eff = b.eff
		}
		m.mu.Unlock()
		key := limit{name, eff.MaxResources()}
		if strings.TrimSpace(key.max.CPU) == "" && strings.TrimSpace(key.max.Memory) == "" {
			continue
		}
		w, ok := warnings[key]
		if !ok {
			d, _ := openshell.LookupDriver(string(name))
			w = m.sharedLimitsWarning(d, key.max)
			warnings[key] = w
		}
		if w != "" {
			views[i].Warnings = append(slices.Clip(views[i].Warnings), w)
		}
	}
}

// sharedLimitsWarning is sharedLimitsWarnings' text for driver d; "" when
// what its sandboxes get fits the maximum.
func (m *Manager) sharedLimitsWarning(d openshell.Driver, max config.OpenShellResourcesConfig) string {
	var shared *packs.Resources
	if m.opts.GatewayResources != nil {
		if res, err := m.opts.GatewayResources(); err == nil {
			shared = &res
		}
	}
	v := sharedResourcesViolation(d, shared, max)
	switch {
	case v == nil:
		return ""
	case shared == nil:
		return v.Message + ", so it cannot start"
	}
	return v.Message + ", so it cannot start until that is lowered (`defenseclaw sandbox doctor --fix`)"
}

// decorate adds what view leaves out because it needs I/O or other locks:
// the egress counts and the snapshot, with its acceptance (accepted, the
// record's Accepted) when it applies. The egress counts sum up the
// sandbox's destinations (egressSummary), the proxy's live counts merged
// in. Callers must not hold Manager.mu.
func (m *Manager) decorate(v *sandboxapi.Sandbox, proxy ProxyControl, bindingID string, accepted *acceptedSnapshot) {
	live := map[string]egress.DestinationStats{}
	if proxy != nil && proxy.Counter() != nil && bindingID != "" {
		for _, d := range proxy.Counter().DestinationsFor(bindingID) {
			if !d.Contacted && harnessFetchHost(v.Harness, d.Host, 0) {
				continue
			}
			live[strings.ToLower(d.Host)] = d
		}
	}
	v.Egress = m.egressSummary(v.Name, v.Harness, live)
	if snap, err := m.ws.LoadSnapshot(m.opts.DataDir, v.Name); err == nil && snap != nil {
		info := &sandboxapi.SnapshotInfo{Kind: string(snap.Kind), CreatedAt: snap.CreatedAt}
		if snap.Git != nil {
			info.Ref = snap.Git.Ref
		}
		if snap.UndoneAt != nil {
			info.UndoneAt = *snap.UndoneAt
		}
		if accepted.acceptedFor(snap, v.Session) {
			info.AcceptedAt = accepted.At
		}
		v.Snapshot = info
	}
}

// view renders the locked part of a box's API form. Callers hold
// Manager.mu and call decorate after releasing it.
func (m *Manager) view(b *box) sandboxapi.Sandbox {
	r := b.rec
	v := sandboxapi.Sandbox{
		Name: r.Name, ID: r.ID, Harness: r.Harness, Pack: r.Pack, PackDigest: r.PackDigest,
		Profile: r.Profile, NetworkMode: r.NetworkMode, Approvals: r.Approvals, Yolo: launchYolo(b),
		WorkdirMode: r.WorkdirMode, Project: r.Project, Workdir: r.Workdir, Image: r.Image, ImageID: r.ImageID,
		RunImage: r.RunImage, RunImageID: r.RunImageID, Driver: r.Driver, DriverReason: r.DriverReason,
		HarnessVersion: r.HarnessVersion, HookContract: r.HookContract, TamperTier: r.TamperTier,
		CreatedAt: r.CreatedAt, Session: r.Sessions, Workspace: r.Workspace, MCP: r.MCP, Violations: r.Violations, Warnings: r.Warnings,
		Orphaned: b.orphaned, NestedRepos: nestedView(r.Guard), ProcessTree: b.processTreeOn(),
		Launch:      sandboxapi.Launch{Yolo: launchYolo(b), CredentialProfile: r.CredentialProfile, BedrockRegion: r.BedrockRegion},
		PhaseReason: r.PhaseReason,
		Credentials: slices.Clone(r.Credentials), HostPorts: slices.Clone(r.HostPorts),
	}
	if spec, ok := harness.Get(r.Harness); ok {
		v.HarnessName = spec.DisplayName
	}
	switch {
	case b.retained:
		v.Phase = string(audit.SandboxPhaseDeleted)
	case b.missing:
		v.Phase = string(phaseMissing)
	case b.sb != nil:
		v.Phase = strings.ToLower(string(b.sb.Status.Phase))
		v.ExitCode = b.sb.Status.ExitCode
		if v.ID == "" {
			v.ID = b.sb.ID
		}
		for _, ep := range b.sb.Status.EndpointStatuses {
			v.Endpoints = append(v.Endpoints, sandboxapi.Endpoint{
				Host: ep.Host, Ports: ep.Ports, Path: ep.Path, Result: string(ep.LastResult), ReportedAt: ep.LastReportedAt,
			})
		}
	case b.creating:
		v.Phase = string(audit.SandboxPhaseCreating)
	default:
		v.Phase = string(audit.SandboxPhaseUnknown)
	}
	if b.phase == audit.SandboxPhaseReady && !b.started.IsZero() {
		started := b.started
		// Became ready before this daemon adopted it (record.ReadyAt), and
		// not before OpenShell created it (a sandbox made again since).
		if ready := r.ReadyAt; !ready.IsZero() && ready.Before(started) && (b.sb == nil || !ready.Before(b.sb.CreatedAt)) {
			started = ready
		}
		v.StartedAt = started
		v.UptimeSeconds = int64(m.now().Sub(started) / time.Second)
	}
	if b.phase == audit.SandboxPhaseReady && !openshell.RunsSandboxes(r.SessionRelease) {
		v.Warnings = append(slices.Clone(v.Warnings), oldSupervisorWarning)
	}
	v.Hooks = sandboxapi.HookCoverage{
		LastHookAt: b.hooks.lastHook, LastOTLPAt: b.hooks.lastOTLP, HookRequests: b.hooks.requests,
		ToolCalls: b.hooks.toolCalls, ToolBlocked: b.hooks.toolBlocked, ToolAsked: b.hooks.toolAsked, PromptBlocked: b.hooks.promptBlocked, LastBlocked: b.hooks.lastBlocked,
		Events: maps.Clone(b.hooks.events), OtherEvents: b.hooks.otherEvents,
		Tampered: b.hooks.tampered, LastTamperAt: b.hooks.lastTamper,
		HookFailed: b.hooks.failed, LastHookFailure: b.hooks.lastFailure, LastHookFailureAt: b.hooks.lastFailureAt,
		LastHookFailureCause: b.hooks.failureCause, HooksAnsweredAt: b.hooks.answeredAt,
		ModelKeyRejected: b.hooks.modelRejected, ModelKeyRejectedAt: b.hooks.modelRejectedAt,
		Silent: !b.silentSince.IsZero(), SilentSince: b.silentSince,
		IngressRefused: b.hooks.ingressRefused, LastIngressRefusedAt: b.hooks.lastIngressRefused,
		Unreachable: !b.reach.since.IsZero(), UnreachableSince: b.reach.since, UnreachableReason: b.reach.reason,
		NoHookYet: !b.reach.since.IsZero() && b.reach.noHookYet,
	}
	if b.placeholderInSessionLocked() {
		v.Hooks.PlaceholderRefusedAt = b.hooks.placeholderAt
	}
	v.UnflushedAt, v.EndedAt = r.UnflushedAt, r.EndedAt
	for _, a := range m.approvals {
		if a.sandbox == r.Name && a.status == sandboxapi.ApprovalPending {
			v.PendingApprovals++
		}
	}
	// What silent hooks lead to, as checkHookSilence decides it: under a
	// policy that is not resolved, the fail-closed response.
	var after time.Duration
	v.Hooks.OnSilence, after = silenceResponse(r.TamperTier, b.eff)
	v.Hooks.SilenceAfter = packs.ShortDuration(after)
	running := b.phase == audit.SandboxPhaseReady && !b.started.IsZero()
	if running {
		v.SessionYolo = launchYolo(b)
		if r.SessionYolo != nil {
			v.SessionYolo = *r.SessionYolo
		}
	}
	if e := b.eff; e != nil {
		// The policy the sandbox runs under now: every configuration change
		// re-resolves it (refreshEgress), so an administrator's change
		// applies to it; the record keeps what it was created with, and so
		// do the create-time clamps, which the current ones replace.
		v.Profile, v.NetworkMode, v.Approvals = e.Profile, e.NetworkMode, e.Approvals
		if f, ok := effectiveFloor(e); ok {
			v.UserApprovals = strings.ToLower(strings.TrimSpace(f.UserApprovals))
		}
		v.HostPorts = slices.Clone(e.MCP.HostPorts)
		if e.Pack != nil {
			v.Pack, v.PackDigest = e.Pack.Name, e.Pack.Digest
		}
		if rp := e.RepoPolicy; rp != nil {
			// The TUI's sandbox detail names it like the banner (GAP-0244).
			v.RepoPolicy = &sandboxapi.RepoPolicy{Path: rp.Source, Digest: rp.Digest, Tightened: slices.Clone(e.RepoTightened)}
		}
		v.Violations = wireViolations(b.violations)
		v.Warnings = append(slices.Clip(v.Warnings), postureDrift(r, e)...)
		if running {
			v.Warnings = append(v.Warnings, sessionDrift(r, e, v.SessionYolo, v.Yolo)...)
		}
	}
	// A driver without per-sandbox limits (vm) is judged by what every
	// sandbox of it gets now, which needs I/O (sharedLimitsWarnings).
	if d, _ := openshell.LookupDriver(r.Driver); d.SandboxLimits {
		if res := resourceViolation(r.Resources, b.eff.MaxResources()); res != nil && !b.retained {
			v.Warnings = append(slices.Clip(v.Warnings), res.Message+
				" (it keeps its current limits until it stops, and cannot start again)")
		}
	}
	if created := recordDriver(r); b.elsewhere != "" && b.otherDriver {
		v.Warnings = append(slices.Clip(v.Warnings), "this sandbox was created on the "+string(created)+
			" compute driver, which the gateway no longer runs; it cannot start, or be pulled, until the gateway runs "+string(created)+
			" again (`defenseclaw sandbox setup`), and deleting it releases DefenseClaw's side only")
	} else if b.elsewhere != "" {
		v.Warnings = append(slices.Clip(v.Warnings), "this sandbox was created on "+b.elsewhere+
			", not the gateway DefenseClaw is connected to; DefenseClaw keeps it until it connects there again (openshell.gateway), "+
			"or until you delete it, which releases DefenseClaw's side only")
	}
	displaySafe(&v)
	if b.unrecorded {
		v.Warnings = append(slices.Clip(v.Warnings),
			"DefenseClaw has no readable record of this sandbox; it has no web egress and cannot start again until you delete it")
	}
	return v
}
