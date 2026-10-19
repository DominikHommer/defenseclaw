// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

var errNativeModelCustody = errors.New("native model custody remains sealed or incomplete")

const nativeModelPublicationLimit = 5 * time.Second

// nativeModelChannel is the host-owned model endpoint. The current Anthropic
// adapter satisfies this interface; no guest-selected endpoint or credential
// can be registered through it. SealAndQuiesce must seal before waiting and
// remain sealed even when ctx expires.
type nativeModelChannel interface {
	SealAndQuiesce(context.Context) error
	Close(context.Context) error
	// This private method prevents a producer from registering a live
	// adapter under another session's custody key or policy epoch.
	nativeModelLeaseBinding() (sandboxruntime.SessionIdentity, sandboxruntime.PolicyAuthorityBinding)
}

// nativeModelLease retains the model channel and, through the two callbacks,
// the same session's native process, durable binding and held endpoint assets.
// The trusted producer must register it before making any listener or process
// reachable. RevokeOwned must stop/wait and durably revoke without draining a
// model request or reentering ConfigManager/LaunchGate. DrainEndpoint releases
// only after the native revoke and model Close succeed. The current offline
// producer does not construct this lease.
type nativeModelLease struct {
	identity      sandboxruntime.SessionIdentity
	authority     sandboxruntime.PolicyAuthorityBinding
	model         nativeModelChannel
	revokeOwned   func(context.Context) error
	drainEndpoint func(context.Context) error
	op            chan struct{}
	revokedDone   chan struct{}
	sealed        atomic.Bool
	revoked       atomic.Bool
	modelClosed   bool
	endpointDone  bool
}

type nativeModelRegistry struct {
	mu          sync.Mutex
	leases      map[string]*nativeModelLease
	rotating    bool
	publishing  int
	draining    bool
	quarantined bool
	failed      bool
	lastCleanup error
}

func missingNativeModelChannel(model nativeModelChannel) bool {
	if model == nil {
		return true
	}
	value := reflect.ValueOf(model)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (o *sidecarSandboxLaunchOwner) retainNativeModelLease(identity sandboxruntime.SessionIdentity,
	authority sandboxruntime.PolicyAuthorityBinding, model nativeModelChannel,
	revokeOwned, drainEndpoint func(context.Context) error,
) error {
	if o == nil || identity.Validate() != nil || authority.Generation == 0 ||
		missingNativeModelChannel(model) || revokeOwned == nil || drainEndpoint == nil {
		return errNativeModelCustody
	}
	modelIdentity, modelAuthority := model.nativeModelLeaseBinding()
	if sandboxruntime.ValidateOwnedSession(modelIdentity, identity) != nil ||
		modelAuthority != authority {
		return errNativeModelCustody
	}
	o.models.mu.Lock()
	defer o.models.mu.Unlock()
	if o.models.rotating || o.models.publishing != 0 || o.models.quarantined || o.models.failed || o.current() != authority {
		return errNativeModelCustody
	}
	if o.models.leases == nil {
		o.models.leases = make(map[string]*nativeModelLease)
	}
	if _, exists := o.models.leases[identity.ID]; exists {
		return errNativeModelCustody
	}
	o.models.leases[identity.ID] = &nativeModelLease{
		identity: identity, authority: authority, model: model,
		revokeOwned: revokeOwned, drainEndpoint: drainEndpoint,
		op: make(chan struct{}, 1), revokedDone: make(chan struct{}),
	}
	return nil
}

func (o *sidecarSandboxLaunchOwner) beginNativeModelRotation() ([]*nativeModelLease, error) {
	if o == nil {
		return nil, errNativeModelCustody
	}
	o.models.mu.Lock()
	defer o.models.mu.Unlock()
	if o.models.rotating || o.models.failed {
		return nil, errNativeModelCustody
	}
	o.models.rotating = true
	o.models.quarantined = true
	keys := make([]string, 0, len(o.models.leases))
	for key := range o.models.leases {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	leases := make([]*nativeModelLease, 0, len(keys))
	for _, key := range keys {
		leases = append(leases, o.models.leases[key])
	}
	return leases, nil
}

func (lease *nativeModelLease) lock(ctx context.Context) error {
	if lease == nil || ctx == nil {
		return errNativeModelCustody
	}
	select {
	case lease.op <- struct{}{}:
		return nil
	case <-ctx.Done():
		return errors.Join(errNativeModelCustody, ctx.Err())
	}
}

func (lease *nativeModelLease) unlock() { <-lease.op }

func (lease *nativeModelLease) seal(ctx context.Context) error {
	if lease.sealed.Load() {
		return nil
	}
	if err := lease.model.SealAndQuiesce(ctx); err != nil {
		return errors.Join(errNativeModelCustody, err)
	}
	lease.sealed.Store(true)
	return nil
}

func (lease *nativeModelLease) revoke(ctx context.Context) error {
	// A later publication must not wait on a Close holding op after the
	// native process and durable binding were already revoked.
	if lease.revoked.Load() {
		return nil
	}
	return lease.revokeAfterInitialCheck(ctx)
}

// revokeAfterInitialCheck also handles a successful durable revoke that races
// the first status read and a terminal Close that wins the operation slot.
func (lease *nativeModelLease) revokeAfterInitialCheck(ctx context.Context) error {
	// Terminal Close may win op for a long model drain immediately after
	// revocation. Wait for either the operation slot or its durable-revoke
	// completion; publication must never wait on that drain under config locks.
	select {
	case <-lease.revokedDone:
		return nil
	case lease.op <- struct{}{}:
	case <-ctx.Done():
		return errors.Join(errNativeModelCustody, ctx.Err())
	}
	defer lease.unlock()
	if lease.revoked.Load() {
		return nil
	}
	if err := lease.revokeOwned(ctx); err != nil {
		return errors.Join(errNativeModelCustody, err)
	}
	lease.revoked.Store(true)
	close(lease.revokedDone)
	return nil
}

func (lease *nativeModelLease) drain(ctx context.Context) error {
	if err := lease.lock(ctx); err != nil {
		return err
	}
	defer lease.unlock()
	if !lease.revoked.Load() {
		return errNativeModelCustody
	}
	if !lease.modelClosed {
		if err := lease.model.Close(ctx); err != nil {
			return errors.Join(errNativeModelCustody, err)
		}
		lease.modelClosed = true
	}
	if !lease.endpointDone {
		if err := lease.drainEndpoint(ctx); err != nil {
			return errors.Join(errNativeModelCustody, err)
		}
		lease.endpointDone = true
	}
	return nil
}

// closeNativeModelLease is the normal session terminal path. The caller must
// retain this owner on any error. Publication may race this path: idempotent
// lease phases serialize on op, while the publication snapshot keeps custody.
func (o *sidecarSandboxLaunchOwner) closeNativeModelLease(ctx context.Context,
	identity sandboxruntime.SessionIdentity,
) error {
	if o == nil || ctx == nil {
		return errNativeModelCustody
	}
	o.models.mu.Lock()
	lease := o.models.leases[identity.ID]
	o.models.mu.Unlock()
	if lease == nil || sandboxruntime.ValidateOwnedSession(lease.identity, identity) != nil {
		return errNativeModelCustody
	}
	sealErr := lease.seal(ctx)
	revokeErr := lease.revoke(ctx)
	var drainErr error
	if revokeErr == nil {
		drainErr = lease.drain(ctx)
	}
	err := errors.Join(sealErr, revokeErr, drainErr)
	o.models.mu.Lock()
	if err == nil {
		if o.models.leases[identity.ID] == lease {
			delete(o.models.leases, identity.ID)
		}
		if len(o.models.leases) == 0 && !o.models.rotating &&
			o.models.publishing == 0 && !o.models.draining && !o.models.failed {
			o.models.quarantined = false
			o.models.lastCleanup = nil
		}
	} else {
		// A terminal cleanup refusal retains the lease and blocks admission
		// until the same owner completes a bounded retry.
		o.models.quarantined = true
		o.models.lastCleanup = err
	}
	o.models.mu.Unlock()
	return err
}

// cleanupRetainedNativeModels elects one post-reload drainer without waiting
// for another drainer. A model Close may itself reenter Reload, so nested
// callbacks must return while the original owner keeps every retained lease.
func (o *sidecarSandboxLaunchOwner) cleanupRetainedNativeModels(ctx context.Context) (cleanupErr error) {
	if o == nil || ctx == nil {
		return errNativeModelCustody
	}
	o.models.mu.Lock()
	if !o.models.quarantined || o.models.draining {
		o.models.mu.Unlock()
		return nil
	}
	if len(o.models.leases) == 0 {
		if !o.models.rotating && o.models.publishing == 0 && !o.models.failed {
			o.models.quarantined = false
		}
		o.models.lastCleanup = nil
		o.models.mu.Unlock()
		return nil
	}
	o.models.draining = true
	keys := make([]string, 0, len(o.models.leases))
	for key := range o.models.leases {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	leases := make([]*nativeModelLease, 0, len(keys))
	for _, key := range keys {
		leases = append(leases, o.models.leases[key])
	}
	o.models.mu.Unlock()
	defer func() {
		o.models.mu.Lock()
		o.models.draining = false
		o.models.lastCleanup = cleanupErr
		if cleanupErr == nil && len(o.models.leases) == 0 &&
			!o.models.rotating && o.models.publishing == 0 && !o.models.failed {
			o.models.quarantined = false
		}
		o.models.mu.Unlock()
	}()
	for _, lease := range leases {
		sealErr := lease.seal(ctx)
		revokeErr := lease.revoke(ctx)
		var drainErr error
		if revokeErr == nil {
			drainErr = lease.drain(ctx)
		}
		if err := errors.Join(sealErr, revokeErr, drainErr); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		o.models.mu.Lock()
		if o.models.leases[lease.identity.ID] == lease {
			delete(o.models.leases, lease.identity.ID)
		}
		o.models.mu.Unlock()
	}
	return cleanupErr
}

// drainNativeModelsAfterReload runs from ConfigManager's deferred callback,
// after its mutex is released. It never reports a postcommit drain failure as
// a rejected generation. A failed or canceled cleanup stays owned and sealed;
// any later reload can retry it, and no new model lease can register meanwhile.
func (s *Sidecar) drainNativeModelsAfterReload(ctx context.Context) {
	if s == nil || ctx == nil {
		return
	}
	owner := s.sandboxLaunchOwner.Load()
	if owner == nil {
		return
	}
	owner.models.mu.Lock()
	pending := owner.models.quarantined
	owner.models.mu.Unlock()
	if !pending {
		return
	}
	// Cleanup has its own finite host lifetime even if the triggering
	// request was canceled immediately after authority publication.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), nativeModelPublicationLimit)
	defer cancel()
	_ = owner.cleanupRetainedNativeModels(cleanupCtx)
}
