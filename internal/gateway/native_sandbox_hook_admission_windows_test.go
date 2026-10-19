// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

type privateWindowsHookCause struct{}

func (privateWindowsHookCause) Error() string { panic("producer values must never be formatted") }

type fakeWindowsHookEvent struct {
	mu                             sync.Mutex
	set, observePanic, signalPanic bool
	observeErr, signalErr          error
	observations, signals          int
	notify                         chan struct{}
}

func (event *fakeWindowsHookEvent) Signaled() (bool, error) {
	event.mu.Lock()
	defer event.mu.Unlock()
	event.observations++
	if event.notify != nil {
		select {
		case event.notify <- struct{}{}:
		default:
		}
	}
	if event.observePanic {
		panic(privateWindowsHookCause{})
	}
	return event.set, event.observeErr
}
func (event *fakeWindowsHookEvent) Signal() error {
	event.mu.Lock()
	defer event.mu.Unlock()
	event.signals++
	if event.signalPanic {
		panic(privateWindowsHookCause{})
	}
	if event.signalErr != nil {
		return event.signalErr
	}
	event.set = true
	return nil
}
func (event *fakeWindowsHookEvent) nextObservation() <-chan struct{} {
	event.mu.Lock()
	defer event.mu.Unlock()
	event.notify = make(chan struct{}, 1)
	return event.notify
}

func syntheticWindowsHookFacts(t *testing.T) (windowsHookPrincipal, []byte) {
	t.Helper()
	user := []byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0}
	container := []byte{1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 42, 0, 0, 0}
	principal, err := newWindowsHookPrincipal(user, container, false, 0x1000, 1)
	if err != nil {
		t.Fatal("synthetic encoding refused")
	}
	return principal, user
}

func syntheticWindowsHookGate(t *testing.T) (*windowsHookAdmission, *fakeWindowsHookEvent, windowsHookPrincipal, context.CancelFunc) {
	t.Helper()
	principal, user := syntheticWindowsHookFacts(t)
	hash := "sha256:" + strings.Repeat("a", 64)
	binding := bridgeproto.Binding{SessionID: "fixed-test", SessionDigest: hash, PolicyDigest: hash, RuntimeDigest: hash, HarnessDigest: hash, PreparationHash: hash}
	owner, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	var nonce [32]byte
	nonce[0] = 7
	event := &fakeWindowsHookEvent{}
	gate, err := newWindowsHookAdmission(owner, binding, 2, nonce, user, event)
	if err != nil {
		t.Fatal("fixed constructor refused")
	}
	user[8]++ // constructor owns an immutable copy of the expected identity
	return gate, event, principal, cancel
}

func bindSyntheticWindowsHookGate(t *testing.T, gate *windowsHookAdmission, principal windowsHookPrincipal) {
	t.Helper()
	if gate.bindSuspended(gate.binding, gate.launch, gate.nonce, principal) != nil {
		t.Fatal("fixed bind refused")
	}
}
func activateSyntheticWindowsHookGate(t *testing.T, gate *windowsHookAdmission, principal windowsHookPrincipal) {
	t.Helper()
	bindSyntheticWindowsHookGate(t, gate, principal)
	if gate.armAdmit(gate.binding, gate.launch, gate.nonce) != nil || gate.observeStarted(gate.binding, gate.launch) != nil {
		t.Fatal("fixed Started refused")
	}
}
func hookRequestContext(t *testing.T, gate *windowsHookAdmission) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(gate.owner, 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func hookResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("bounded fake worker did not finish")
		return nil
	}
}
func pendingWindowsHookRequest(t *testing.T, gate *windowsHookAdmission, event *fakeWindowsHookEvent, principal windowsHookPrincipal, ctx context.Context, handler func(context.Context) error) <-chan error {
	t.Helper()
	observed := event.nextObservation()
	result := make(chan error, 1)
	go func() { result <- gate.withAuthenticatedRequest(ctx, principal, handler) }()
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("pending request did not observe event")
	}
	gate.mu.Lock() // first observation occurs while this lock spans slot claim
	claimed := gate.slot
	gate.mu.Unlock()
	if !claimed {
		t.Fatal("pending slot was not claimed")
	}
	return result
}

func TestWindowsHookAdmissionIsClosedUntilExactStartedAndHoldsOneEarlyRequest(t *testing.T) {
	gate, event, principal, _ := syntheticWindowsHookGate(t)
	ctx := hookRequestContext(t, gate)
	var calls atomic.Int32
	handler := func(context.Context) error { calls.Add(1); return nil }
	if gate.withAuthenticatedRequest(ctx, principal, handler) == nil || calls.Load() != 0 {
		t.Fatal("unbound handler ran")
	}
	bindSyntheticWindowsHookGate(t, gate, principal)
	result := pendingWindowsHookRequest(t, gate, event, principal, ctx, handler)
	if calls.Load() != 0 {
		t.Fatal("bound endpoint evaluated before Started")
	}
	if gate.armAdmit(gate.binding, gate.launch, gate.nonce) != nil || calls.Load() != 0 {
		t.Fatal("ACK activated endpoint")
	}
	if gate.observeStarted(gate.binding, gate.launch) != nil || hookResult(t, result) != nil || calls.Load() != 1 {
		t.Fatal("exact Started did not release one request")
	}
	if gate.seal() != nil {
		t.Fatal("fixed seal failed")
	}
}

func TestWindowsHookAdmissionCorrelationReplaysAndMalformedPrincipalsSeal(t *testing.T) {
	for _, mutation := range []string{"binding", "launch", "nonce", "user", "container", "padding", "duplicate_bind", "wrong_ack", "duplicate_ack", "early_started", "wrong_started", "duplicate_started"} {
		t.Run(mutation, func(t *testing.T) {
			gate, _, principal, _ := syntheticWindowsHookGate(t)
			binding, launch, nonce := gate.binding, gate.launch, gate.nonce
			switch mutation {
			case "binding":
				binding.SessionID = "other"
			case "launch":
				launch++
			case "nonce":
				nonce[0]++
			case "user":
				principal.user[8]++
			case "container":
				principal.containerSize = 1
			case "padding":
				principal.container[67] = 1
			}
			var err error
			if mutation == "binding" || mutation == "launch" || mutation == "nonce" || mutation == "user" || mutation == "container" || mutation == "padding" {
				err = gate.bindSuspended(binding, launch, nonce, principal)
			} else {
				bindSyntheticWindowsHookGate(t, gate, principal)
				switch mutation {
				case "duplicate_bind":
					err = gate.bindSuspended(binding, launch, nonce, principal)
				case "wrong_ack":
					nonce[0]++
					err = gate.armAdmit(binding, launch, nonce)
				case "early_started":
					err = gate.observeStarted(binding, launch)
				default:
					if gate.armAdmit(binding, launch, nonce) != nil {
						t.Fatal("valid ACK refused")
					}
					switch mutation {
					case "duplicate_ack":
						err = gate.armAdmit(binding, launch, nonce)
					case "wrong_started":
						err = gate.observeStarted(binding, launch+1)
					case "duplicate_started":
						if gate.observeStarted(binding, launch) != nil {
							t.Fatal("valid Started refused")
						}
						err = gate.observeStarted(binding, launch)
					}
				}
			}
			if !errors.Is(err, errWindowsHookAdmission) || gate.phase != windowsHookSealed || gate.armAdmit(binding, launch, nonce) == nil {
				t.Fatal("bad transaction reopened")
			}
		})
	}
}

func TestWindowsHookAdmissionComparesEveryCopiedClientTokenFact(t *testing.T) {
	gate, _, principal, _ := syntheticWindowsHookGate(t)
	activateSyntheticWindowsHookGate(t, gate, principal)
	ctx := hookRequestContext(t, gate)
	for _, change := range []func(*windowsHookPrincipal){
		func(p *windowsHookPrincipal) { p.user[8]++ },
		func(p *windowsHookPrincipal) { p.container[12]++ },
		func(p *windowsHookPrincipal) { p.isAppContainer = !p.isAppContainer },
		func(p *windowsHookPrincipal) { p.integrity++ },
		func(p *windowsHookPrincipal) { p.session++ },
	} {
		wrong := principal
		change(&wrong)
		if gate.withAuthenticatedRequest(ctx, wrong, func(context.Context) error { t.Fatal("wrong client evaluated"); return nil }) == nil {
			t.Fatal("wrong native client admitted")
		}
	}
	if gate.phase != windowsHookActive || gate.withAuthenticatedRequest(ctx, principal, func(context.Context) error { return nil }) != nil {
		t.Fatal("wrong client caused binding adoption or session DoS")
	}
	_ = gate.seal()
}

func TestWindowsHookAdmissionSlotCancellationDeadlineAndOwnerRevocation(t *testing.T) {
	gate, event, principal, ownerCancel := syntheticWindowsHookGate(t)
	bindSyntheticWindowsHookGate(t, gate, principal)
	ctx, cancel := context.WithCancel(hookRequestContext(t, gate))
	result := pendingWindowsHookRequest(t, gate, event, principal, ctx, func(context.Context) error { t.Error("cancelled request evaluated"); return nil })
	if !errors.Is(gate.withAuthenticatedRequest(hookRequestContext(t, gate), principal, func(context.Context) error { t.Fatal("second request queued"); return nil }), errWindowsHookBusy) {
		t.Fatal("slot was unbounded")
	}
	cancel()
	if hookResult(t, result) == nil || gate.slot || gate.phase != windowsHookBoundAwaitStarted {
		t.Fatal("request cancellation did not release only its slot")
	}
	result = pendingWindowsHookRequest(t, gate, event, principal, hookRequestContext(t, gate), func(context.Context) error { t.Error("owner-cancelled request evaluated"); return nil })
	ownerCancel()
	if hookResult(t, result) == nil || gate.phase != windowsHookSealed || !gate.drainClosed {
		t.Fatal("owner cancellation did not seal/drain")
	}

	expired, _, identity, _ := syntheticWindowsHookGate(t)
	bindSyntheticWindowsHookGate(t, expired, identity)
	expired.pendingUntil = time.Now().Add(-time.Second)
	if expired.withAuthenticatedRequest(hookRequestContext(t, expired), identity, func(context.Context) error { t.Fatal("expired pending evaluated"); return nil }) == nil || expired.phase != windowsHookSealed {
		t.Fatal("pending deadline did not refuse")
	}
}

func TestWindowsHookAdmissionActiveRequestLinksIndependentContextToOwner(t *testing.T) {
	gate, _, principal, ownerCancel := syntheticWindowsHookGate(t)
	activateSyntheticWindowsHookGate(t, gate, principal)
	independent, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- gate.withAuthenticatedRequest(independent, principal, func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("active request did not enter")
	}
	ownerCancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || independent.Err() != nil || gate.phase != windowsHookSealed || !gate.drainClosed {
			t.Fatal("active owner cancellation did not seal/drain independently")
		}
	case <-time.After(time.Second):
		t.Fatal("active request followed only its unrelated caller timeout")
	}
}

func TestWindowsHookAdmissionSealIsStickyPreStopAndDrainsAdmittedWork(t *testing.T) {
	gate, event, principal, _ := syntheticWindowsHookGate(t)
	activateSyntheticWindowsHookGate(t, gate, principal)
	entered, release := make(chan struct{}), make(chan struct{})
	requestLifetime := make(chan context.Context, 1)
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	result := make(chan error, 1)
	go func() {
		result <- gate.withAuthenticatedRequest(hookRequestContext(t, gate), principal, func(ctx context.Context) error { requestLifetime <- ctx; close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("active handler did not enter")
	}
	if gate.seal() != nil || gate.phase != windowsHookSealed {
		t.Fatal("host seal failed")
	}
	select {
	case <-(<-requestLifetime).Done():
	default:
		t.Fatal("seal did not cancel the admitted request before Stop")
	}
	// Model the SAME existing owner's next native Stop boundary. Seal did not
	// wait for the request, and it precedes that boundary even during drain.
	event.mu.Lock()
	signals := event.signals
	event.set = false // hostile/reset observation cannot reopen the host latch
	event.mu.Unlock()
	if signals != 1 {
		t.Fatal("Stop preceded its exact event signal")
	}
	select {
	case <-gate.drained:
		t.Fatal("inflight work was falsely drained")
	default:
	}
	if gate.withAuthenticatedRequest(hookRequestContext(t, gate), principal, func(context.Context) error { t.Fatal("sealed handler evaluated"); return nil }) == nil {
		t.Fatal("seal reopened")
	}
	releaseOnce.Do(func() { close(release) })
	if hookResult(t, result) != nil {
		t.Fatal("already-admitted callback failed")
	}
	select {
	case <-gate.drained:
	default:
		t.Fatal("callback release did not drain")
	}
	if gate.seal() != nil {
		t.Fatal("repeated seal failed")
	}
	event.mu.Lock()
	defer event.mu.Unlock()
	if event.signals != 1 {
		t.Fatal("seal retried an uncertain native action")
	}
}

func TestWindowsHookAdmissionEventFailuresAndHandlerPanicNeverOpenOrLeakValues(t *testing.T) {
	for _, mode := range []string{"observe_error", "observe_panic", "signal_error", "signal_panic", "signaled"} {
		t.Run(mode, func(t *testing.T) {
			gate, event, principal, _ := syntheticWindowsHookGate(t)
			activateSyntheticWindowsHookGate(t, gate, principal)
			event.mu.Lock()
			switch mode {
			case "observe_error":
				event.observeErr = privateWindowsHookCause{}
			case "observe_panic":
				event.observePanic = true
			case "signal_error":
				event.signalErr = privateWindowsHookCause{}
			case "signal_panic":
				event.signalPanic = true
			case "signaled":
				event.set = true
			}
			event.mu.Unlock()
			if mode == "signal_error" || mode == "signal_panic" {
				if !errors.Is(gate.seal(), errWindowsHookEvent) || !errors.Is(gate.seal(), errWindowsHookEvent) {
					t.Fatal("failed signal was not sticky")
				}
			} else if gate.withAuthenticatedRequest(hookRequestContext(t, gate), principal, func(context.Context) error { t.Fatal("bad event evaluated"); return nil }) == nil {
				t.Fatal("bad event admitted")
			}
			if gate.phase != windowsHookSealed || gate.seal() != nil && mode == "signaled" {
				t.Fatal("event refusal reopened")
			}
			if text := gate.seal(); text != nil && text.Error() != errWindowsHookEvent.Error() {
				t.Fatal("producer error text escaped")
			}
		})
	}
	gate, event, principal, _ := syntheticWindowsHookGate(t)
	activateSyntheticWindowsHookGate(t, gate, principal)
	func() {
		defer func() {
			if _, ok := recover().(privateWindowsHookCause); !ok {
				t.Error("handler panic was swallowed or changed")
			}
		}()
		_ = gate.withAuthenticatedRequest(hookRequestContext(t, gate), principal, func(context.Context) error { panic(privateWindowsHookCause{}) })
	}()
	if gate.phase != windowsHookSealed || gate.slot || !gate.drainClosed {
		t.Fatal("panic left admission or slot live")
	}
	event.mu.Lock()
	defer event.mu.Unlock()
	if event.signals != 1 {
		t.Fatal("panic did not seal once")
	}
}

func TestWindowsHookAdmissionConstructorHasNoAmbientFallbackAndRejectsEncoding(t *testing.T) {
	for _, sid := range [][]byte{nil, {1}, {2, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0}, {1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0}} {
		if _, err := newWindowsHookPrincipal(sid, sid, false, 0, 0); err == nil {
			t.Fatal("malformed native SID encoding admitted")
		}
	}
	gate, _, principal, _ := syntheticWindowsHookGate(t)
	var typedNil *fakeWindowsHookEvent
	if _, err := newWindowsHookAdmission(gate.owner, gate.binding, gate.launch, gate.nonce, principal.user[:principal.userSize], typedNil); err == nil {
		t.Fatal("typed nil event admitted")
	}
	if _, err := newWindowsHookAdmission(context.Background(), gate.binding, gate.launch, gate.nonce, principal.user[:principal.userSize], &fakeWindowsHookEvent{}); err == nil {
		t.Fatal("unbounded owner admitted")
	}
	if gate.withAuthenticatedRequest(context.Background(), principal, func(context.Context) error { t.Fatal("unbounded request evaluated"); return nil }) == nil {
		t.Fatal("unbounded request admitted")
	}
}
