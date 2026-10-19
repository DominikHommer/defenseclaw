// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

var (
	errWindowsHookAdmission = errors.New("Windows native hook admission refused")
	errWindowsHookBusy      = errors.New("Windows native hook request slot unavailable")
	errWindowsHookEvent     = errors.New("Windows native hook revocation unavailable")
)

const windowsHookPendingLimit = 4 * time.Second // below the peer's five-second idle bound
const windowsHookEventPoll = 10 * time.Millisecond

// Implementations must perform only bounded zero-time observation/SetEvent on
// the exact owned unnamed event. There is deliberately no Reset method. This
// does not claim that EVENT_MODIFY_STATE itself prevents native ResetEvent.
// The same host asset owner retains and eventually closes the event; this latch
// borrows it through native cleanup. No workload receives an event handle.
type windowsHookRevocation interface {
	Signaled() (bool, error)
	Signal() error
}

func observeWindowsHookEvent(event windowsHookRevocation) (set bool, err error) {
	defer func() {
		if recover() != nil {
			set, err = true, errWindowsHookEvent
		}
	}()
	set, err = event.Signaled()
	if err != nil {
		return true, errWindowsHookEvent
	}
	return set, nil
}

func signalWindowsHookEvent(event windowsHookRevocation) (err error) {
	defer func() {
		if recover() != nil {
			err = errWindowsHookEvent
		}
	}()
	if event.Signal() != nil {
		return errWindowsHookEvent
	}
	return nil
}

// These copied facts must originate from the reviewed suspended child's token,
// or from the actual connected client's token after impersonation. This pure
// constructor validates encoding only, never authenticates a token or peer.
// No JSON/header/path/PID is accepted here as a principal producer.
type windowsHookPrincipal struct {
	user, container         [68]byte
	userSize, containerSize uint8
	isAppContainer          bool
	integrity, session      uint32
}

func windowsHookSID(value []byte) bool {
	return len(value) >= 12 && len(value) <= 68 && value[0] == 1 && value[1] > 0 && value[1] <= 15 && len(value) == 8+4*int(value[1])
}

func newWindowsHookPrincipal(user, container []byte, isAppContainer bool, integrity, session uint32) (windowsHookPrincipal, error) {
	var principal windowsHookPrincipal
	if !windowsHookSID(user) || !windowsHookSID(container) {
		return principal, errWindowsHookAdmission
	}
	copy(principal.user[:], user)
	copy(principal.container[:], container)
	principal.userSize, principal.containerSize = uint8(len(user)), uint8(len(container))
	principal.isAppContainer, principal.integrity, principal.session = isAppContainer, integrity, session
	return principal, nil
}

func (principal windowsHookPrincipal) valid() bool {
	if principal.userSize > 68 || principal.containerSize > 68 || !windowsHookSID(principal.user[:principal.userSize]) || !windowsHookSID(principal.container[:principal.containerSize]) {
		return false
	}
	for _, padding := range principal.user[principal.userSize:] {
		if padding != 0 {
			return false
		}
	}
	for _, padding := range principal.container[principal.containerSize:] {
		if padding != 0 {
			return false
		}
	}
	return true
}

type windowsHookAdmissionPhase uint8

const (
	windowsHookUnbound windowsHookAdmissionPhase = iota
	windowsHookBoundAwaitStarted
	windowsHookActive
	windowsHookSealed
)

// This is an internal endpoint latch, not another launcher or policy handler.
// Its caller retains the same Session/Owner and invokes seal before native Stop.
// No goroutine, watcher, timer, pipe, token query or native allocation starts in
// construction. Production creation/registry remains absent in this first slice.
type windowsHookAdmission struct {
	mu                                        sync.Mutex
	owner                                     context.Context
	ownerDeadline                             time.Time
	binding                                   bridgeproto.Binding
	launch                                    uint64
	nonce                                     [32]byte
	user                                      [68]byte
	userSize                                  uint8
	event                                     windowsHookRevocation
	phase                                     windowsHookAdmissionPhase
	principal                                 windowsHookPrincipal
	admitArmed                                bool
	pendingUntil                              time.Time
	slot                                      bool
	cancelRequest                             context.CancelFunc // only the single retained request slot
	changed, drained                          chan struct{}
	drainClosed, signalAttempted, eventFailed bool
}

func newWindowsHookAdmission(owner context.Context, binding bridgeproto.Binding, launch uint64, nonce [32]byte, expectedUser []byte, event windowsHookRevocation) (*windowsHookAdmission, error) {
	if owner == nil || owner.Err() != nil || binding.Validate() != nil || launch == 0 || nonce == ([32]byte{}) || !windowsHookSID(expectedUser) || event == nil {
		return nil, errWindowsHookAdmission
	}
	value := reflect.ValueOf(event)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, errWindowsHookAdmission
		}
	}
	deadline, bounded := owner.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour {
		return nil, errWindowsHookAdmission
	}
	set, err := observeWindowsHookEvent(event)
	if err != nil || set {
		return nil, errWindowsHookEvent
	}
	gate := &windowsHookAdmission{owner: owner, ownerDeadline: deadline, binding: binding, launch: launch, nonce: nonce, event: event,
		changed: make(chan struct{}), drained: make(chan struct{})}
	copy(gate.user[:], expectedUser)
	gate.userSize = uint8(len(expectedUser))
	return gate, nil // event ownership remains with the existing host asset owner
}

func (gate *windowsHookAdmission) notifyLocked() {
	close(gate.changed)
	gate.changed = make(chan struct{})
}

func (gate *windowsHookAdmission) drainedLocked() {
	if gate.phase == windowsHookSealed && !gate.slot && !gate.drainClosed {
		gate.drainClosed = true
		close(gate.drained)
	}
}

func (gate *windowsHookAdmission) sealLocked() error {
	if gate.phase != windowsHookSealed {
		gate.phase = windowsHookSealed // host admission closes BEFORE cross-process signaling
		if gate.cancelRequest != nil {
			gate.cancelRequest()
		}
		gate.principal = windowsHookPrincipal{}
		gate.nonce = [32]byte{}
		gate.notifyLocked()
	}
	if !gate.signalAttempted {
		gate.signalAttempted = true
		if signalWindowsHookEvent(gate.event) != nil {
			gate.eventFailed = true // sticky; never mistake a failed signal for peer revocation
		}
	}
	gate.drainedLocked()
	if gate.eventFailed {
		return errWindowsHookEvent
	}
	return nil
}

// Seal is synchronous and does not wait for admitted handler work or native
// cleanup. The existing owner must call it before closing protocol pipes/Stop.
// Repeated seal cannot reopen, repeat a possibly uncertain signal, or erase its
// failure. Durable binding revocation and drain remain the existing asset owner.
func (gate *windowsHookAdmission) seal() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.sealLocked()
}

func (gate *windowsHookAdmission) liveLocked() bool {
	if gate.phase == windowsHookSealed {
		return false
	}
	set, err := observeWindowsHookEvent(gate.event)
	if gate.owner.Err() != nil || !time.Now().Before(gate.ownerDeadline) || err != nil || set {
		if err != nil {
			gate.eventFailed = true
		}
		_ = gate.sealLocked()
		return false
	}
	return true
}

func (gate *windowsHookAdmission) correlatedLocked(binding bridgeproto.Binding, launch uint64, nonce [32]byte) bool {
	return binding == gate.binding && launch == gate.launch && subtle.ConstantTimeCompare(nonce[:], gate.nonce[:]) == 1
}

func (gate *windowsHookAdmission) bindSuspended(binding bridgeproto.Binding, launch uint64, nonce [32]byte, principal windowsHookPrincipal) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !gate.liveLocked() || gate.phase != windowsHookUnbound || !gate.correlatedLocked(binding, launch, nonce) ||
		!principal.valid() || principal.userSize != gate.userSize || principal.user != gate.user {
		_ = gate.sealLocked()
		return errWindowsHookAdmission
	}
	gate.principal = principal // value copy; caller mutation cannot change the binding
	gate.phase = windowsHookBoundAwaitStarted
	gate.pendingUntil = time.Now().Add(windowsHookPendingLimit)
	if deadline, _ := gate.owner.Deadline(); deadline.Before(gate.pendingUntil) {
		gate.pendingUntil = deadline
	}
	return nil // binding alone never authorizes handler evaluation
}

// armAdmit belongs inside the existing host's serialized Admit-send transaction
// before bytes are exposed; send failure must seal. It does not claim successful
// delivery, native Resume, or endpoint activation. Started remains mandatory.
func (gate *windowsHookAdmission) armAdmit(binding bridgeproto.Binding, launch uint64, nonce [32]byte) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !gate.liveLocked() || gate.phase != windowsHookBoundAwaitStarted || gate.admitArmed || !time.Now().Before(gate.pendingUntil) || !gate.correlatedLocked(binding, launch, nonce) {
		_ = gate.sealLocked()
		return errWindowsHookAdmission
	}
	gate.admitArmed = true
	return nil
}

func (gate *windowsHookAdmission) observeStarted(binding bridgeproto.Binding, launch uint64) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !gate.liveLocked() || gate.phase != windowsHookBoundAwaitStarted || !gate.admitArmed || !time.Now().Before(gate.pendingUntil) || binding != gate.binding || launch != gate.launch {
		_ = gate.sealLocked()
		return errWindowsHookAdmission
	}
	gate.phase = windowsHookActive
	gate.notifyLocked()
	return nil
}

// withAuthenticatedRequest is entered only AFTER the future pipe adapter has
// queried, compared and reverted the actual connected client's token. No read,
// impersonation, header authentication or policy evaluator is implemented here.
// One caller can wait for immediate startup or execute the existing handler;
// another receives immediate backpressure. Waiting never holds gate.mu. The
// callback remains subject to its caller/owner budgets and existing ingress.
func (gate *windowsHookAdmission) withAuthenticatedRequest(ctx context.Context, principal windowsHookPrincipal, handler func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || handler == nil {
		return errWindowsHookAdmission
	}
	deadline, bounded := ctx.Deadline()
	ownerDeadline, _ := gate.owner.Deadline()
	if !bounded || deadline.After(ownerDeadline) {
		return errWindowsHookAdmission
	}
	gate.mu.Lock()
	if !gate.liveLocked() || gate.phase == windowsHookUnbound || principal != gate.principal {
		gate.mu.Unlock()
		return errWindowsHookAdmission
	}
	if gate.slot {
		gate.mu.Unlock()
		return errWindowsHookBusy
	}
	gate.slot = true
	requestContext, cancelRequest := context.WithCancel(ctx)
	stopOwnerCancel := context.AfterFunc(gate.owner, cancelRequest)
	gate.cancelRequest = cancelRequest
	gate.mu.Unlock()
	defer func() {
		failure := recover()
		stopOwnerCancel()
		cancelRequest()
		gate.mu.Lock()
		gate.slot = false
		gate.cancelRequest = nil
		if failure != nil || gate.owner.Err() != nil {
			_ = gate.sealLocked()
		}
		gate.drainedLocked()
		gate.mu.Unlock()
		if failure != nil {
			panic(failure)
		}
	}()
	for {
		gate.mu.Lock()
		if !gate.liveLocked() || requestContext.Err() != nil || !time.Now().Before(deadline) || principal != gate.principal {
			gate.mu.Unlock()
			return errWindowsHookAdmission
		}
		if gate.phase == windowsHookActive {
			gate.mu.Unlock()
			return handler(requestContext) // admitted before any later seal; existing Close drains it
		}
		if !time.Now().Before(gate.pendingUntil) {
			_ = gate.sealLocked()
			gate.mu.Unlock()
			return errWindowsHookAdmission
		}
		changed := gate.changed
		wait := min(windowsHookEventPoll, time.Until(gate.pendingUntil), time.Until(deadline))
		gate.mu.Unlock()
		timer := time.NewTimer(max(wait, 0))
		select {
		case <-changed:
		case <-requestContext.Done():
		case <-gate.owner.Done():
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}
