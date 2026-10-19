// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

var errNativeHookAssets = errors.New("native sandbox hook assets remain unavailable or owned for cleanup")

// nativeSandboxHookAssets decorates the existing PreparedProcess. It creates
// neither a controller nor policy authority. Only a trusted factory may use it;
// the ordinary manager reservation, HostResolvedRun and LaunchGate still admit
// the exact full session. No production catalog installs this producer.
type nativeSandboxHookAssets struct {
	mu                                                                    sync.Mutex
	op                                                                    chan struct{}
	identity                                                              sandboxruntime.SessionIdentity
	harness                                                               sandboxruntime.HarnessIdentity
	lifetime                                                              context.Context
	connector, contract, bindingID, digest                                string
	closing, attempted, complete, launched, nativeDone, drained, released bool
	cancelPrepare                                                         context.CancelFunc
	process                                                               sandboxruntime.PreparedProcess
	// These private callbacks bind the concrete held Linux objects/endpoint.
	// Tests substitute ordering failures; this is not a provider interface.
	duplicate func() (*os.File, error)
	admission func() bool
	seal      func()
	revoke    func(context.Context) error
	drain     func(context.Context) error
	release   func() error
}

func (assets *nativeSandboxHookAssets) lock(ctx context.Context) error {
	if ctx == nil || assets.op == nil {
		return errNativeHookAssets
	}
	select {
	case assets.op <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (assets *nativeSandboxHookAssets) unlock() { <-assets.op }

func missingNativeHookProcess(process sandboxruntime.PreparedProcess) bool {
	if process == nil {
		return true
	}
	value := reflect.ValueOf(process)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// prepare is the single host-factory handoff. read contains exactly one fixed
// hook slot; no guest path is selected by profile JSON or request headers.
// factory receives an EXCLUSIVE directory duplicate. A nonnil returned process
// consumes that duplicate even on error and must retain uncertain partial
// cleanup. A nil process leaves the duplicate untouched with this owner. Those
// are the existing Backend/Assets transfer rules, not a second custody model.
// The returned assets is always the manager's cleanup process after this call,
// including on failure. Construction must not launch an agent.
func (assets *nativeSandboxHookAssets) prepare(ctx context.Context, spec sandboxruntime.Spec, read []string,
	factory func(context.Context, *os.File, *bridgeproto.Hook) (sandboxruntime.PreparedProcess, error),
) (sandboxruntime.PreparedProcess, error) {
	if assets == nil {
		return nil, errNativeHookAssets
	}
	if factory == nil {
		return assets, errNativeHookAssets
	}
	if err := assets.lock(ctx); err != nil {
		return assets, err
	}
	defer assets.unlock()
	assets.mu.Lock()
	if assets.closing || assets.attempted || assets.duplicate == nil || assets.lifetime == nil || assets.lifetime.Err() != nil || assets.admission == nil || !assets.admission() ||
		sandboxruntime.ValidateOwnedSession(assets.identity, spec.Identity) != nil ||
		spec.Harness != assets.connector || spec.HarnessIdentity != assets.harness || spec.BindingID != assets.bindingID {
		assets.mu.Unlock()
		return assets, errNativeHookAssets
	}
	assets.attempted = true
	preparing, cancel := context.WithCancel(ctx)
	assets.cancelPrepare = cancel
	assets.mu.Unlock()
	defer cancel()
	index := -1
	for i, path := range read {
		if path == bridgeproto.HookDirectory {
			if index >= 0 {
				return assets, errNativeHookAssets
			}
			index = i
		}
	}
	if index < 0 || len(read) > 256 {
		return assets, errNativeHookAssets
	}
	file, err := assets.duplicate()
	if err != nil {
		// An allocated file plus validation error remains retained by the
		// concrete duplicate callback, so a refused handoff loses no owner.
		return assets, err
	}
	if file == nil {
		return assets, errNativeHookAssets
	}
	process, result := factory(preparing, file, &bridgeproto.Hook{SessionID: assets.identity.ID, ReadIndex: uint16(index), ProfileDigest: assets.digest})
	assets.mu.Lock()
	if !missingNativeHookProcess(process) {
		assets.process = process
	} else {
		// The factory did not take ownership. Preserve a failed Close as an
		// uncertain exclusive handle in concrete release custody.
		result = errors.Join(result, assets.retainUnconsumed(file))
	}
	closing := assets.closing
	complete := result == nil && !missingNativeHookProcess(process) && !closing && preparing.Err() == nil && assets.lifetime.Err() == nil && assets.admission()
	assets.complete = complete
	assets.cancelPrepare = nil
	assets.mu.Unlock()
	if !complete {
		return assets, errors.Join(errNativeHookAssets, result, preparing.Err())
	}
	return assets, nil
}

// Installed by Linux construction; it transfers an unconsumed duplicate back
// to the concrete asset owner. The extra method keeps release ordering explicit.
func (assets *nativeSandboxHookAssets) retainUnconsumed(file *os.File) error {
	previous := assets.release
	var uncertain error
	assets.release = func() error {
		if uncertain != nil {
			return uncertain
		}
		if file != nil {
			if err := file.Close(); err != nil {
				uncertain = err
				return err
			}
			file = nil
		}
		return previous()
	}
	return errNativeHookAssets
}

func (assets *nativeSandboxHookAssets) Launch(ctx context.Context, spec sandboxruntime.Spec) (sandboxruntime.Instance, error) {
	if assets == nil {
		return sandboxruntime.Instance{}, errNativeHookAssets
	}
	if err := assets.lock(ctx); err != nil {
		return sandboxruntime.Instance{}, err
	}
	defer assets.unlock()
	assets.mu.Lock()
	if assets.closing || !assets.complete || assets.launched || missingNativeHookProcess(assets.process) || assets.lifetime == nil || assets.lifetime.Err() != nil || assets.admission == nil || !assets.admission() ||
		sandboxruntime.ValidateOwnedSession(assets.identity, spec.Identity) != nil || spec.Harness != assets.connector ||
		spec.HarnessIdentity != assets.harness || spec.BindingID != assets.bindingID {
		assets.mu.Unlock()
		return sandboxruntime.Instance{}, errNativeHookAssets
	}
	assets.launched = true
	process := assets.process
	assets.mu.Unlock()
	return process.Launch(ctx, spec)
}

// Close first seals ingress in memory, then uses the actual prepared process to
// stop and observe native cleanup. Only afterward does it drain the existing
// endpoint and release its independent held files/directory. Underlying Assets
// may close their own grant duplicate after native wait; this owner retains a
// distinct root/socket/profile through endpoint drain. No timeout is completion.
func (assets *nativeSandboxHookAssets) Close(ctx context.Context) error {
	if assets == nil || ctx == nil || assets.seal == nil || assets.revoke == nil || assets.drain == nil {
		return errNativeHookAssets
	}
	assets.mu.Lock()
	assets.closing = true
	if assets.cancelPrepare != nil {
		assets.cancelPrepare()
	}
	assets.mu.Unlock()
	// This callback only seals an in-memory admission latch. A synchronous
	// FileStore operation must not delay the first owned native-stop attempt.
	assets.seal()
	if err := assets.lock(ctx); err != nil {
		return errors.Join(errNativeHookAssets, err)
	}
	defer assets.unlock()
	// retainUnconsumed may replace release while prepare holds op. Never read
	// that mutable callback until the same operation token has been acquired.
	if assets.release == nil {
		return errNativeHookAssets
	}
	if !assets.nativeDone {
		if !missingNativeHookProcess(assets.process) {
			if err := assets.process.Close(ctx); err != nil {
				return errors.Join(errNativeHookAssets, err)
			}
		}
		assets.nativeDone = true
	}
	// The token is host-only. Until durable revocation finishes the sealed
	// endpoint refuses new requests; no guest can use that token elsewhere.
	revokeErr := assets.revoke(ctx)
	if !assets.drained {
		if err := assets.drain(ctx); err != nil {
			return errors.Join(errNativeHookAssets, revokeErr, err)
		}
		assets.drained = true
	}
	if revokeErr != nil {
		return errors.Join(errNativeHookAssets, revokeErr)
	}
	if !assets.released {
		if err := assets.release(); err != nil {
			return errors.Join(errNativeHookAssets, err)
		}
		assets.released = true
	}
	return nil
}

// exactNativeHookEntries bounds both calls and detects a late third entry. Go
// permits nonempty Readdirnames results with nil even at the end; only a later
// empty EOF establishes the terminal observation. The held private directory
// is guest-readonly; a malicious same-UID host can still race these samples.
func exactNativeHookEntries(read func(int) ([]string, error), empty bool) error {
	names, err := read(3)
	if err != nil && err != io.EOF {
		return errNativeHookAssets
	}
	if empty {
		if len(names) != 0 || err != io.EOF {
			return errNativeHookAssets
		}
		return nil
	}
	if len(names) != 2 || !((names[0] == "runtime.json" && names[1] == "ingress.sock") ||
		(names[1] == "runtime.json" && names[0] == "ingress.sock")) {
		return errNativeHookAssets
	}
	if err == nil {
		tail, terminal := read(1)
		if len(tail) != 0 || terminal != io.EOF {
			return errNativeHookAssets
		}
	}
	return nil
}
