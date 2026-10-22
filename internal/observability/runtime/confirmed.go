// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// SpooledEmission is one phase of a replayable lifecycle receipt, off the
// hook path. The producer retires its durable spool item only after both
// phases succeeded.
//
// The persist phase (Confirm false) commits the local row and builds no
// destination work. Intent receives the optional destinations the occurrence
// selects before that commit (pipeline.ProcessSpooled).
//
// The confirm phase (Confirm true) runs after the producer proved its stable
// local row exists; it never inserts another row. Obligations are the
// destinations Intent recorded (Known), or the current routing when none was
// recorded (pipeline.ProjectSpooled). The record is admitted to every
// destination before any acknowledgement is awaited, and the phase succeeds
// only once every destination acknowledged it.
type SpooledEmission struct {
	Confirm     bool
	Intent      func(destinations []string) error
	Obligations []string
	Known       bool
}

// EmitSpooled runs one phase of a replayable receipt (SpooledEmission).
func (runtime *Runtime) EmitSpooled(ctx context.Context, metadata router.Metadata, builder EmitBuilder, emission SpooledEmission) (pipeline.LocalLogOutcome, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || builder == nil || (!emission.Confirm && emission.Intent == nil) {
		return pipeline.LocalLogOutcome{}, &Error{code: ErrorInvalidDependency}
	}
	lease, acquireErr := runtime.manager.Acquire(ctx)
	if acquireErr != nil {
		return pipeline.LocalLogOutcome{}, acquireErr
	}
	defer lease.Release()
	graph := lease.Graph()
	value, ok := lease.Component(LocalLogComponentName)
	local, typed := value.(*localLogComponent)
	if graph == nil || !ok || !typed || local == nil || local.digest != graph.Digest() {
		return pipeline.LocalLogOutcome{}, &Error{code: ErrorComponentUnavailable}
	}
	build := leaseRecordBuilder(ctx, lease, EmitContext{plan: graph.Plan(), digest: graph.Digest(), generation: graph.Generation()}, builder, false)
	if !emission.Confirm {
		return local.ProcessSpooled(ctx, metadata, build, emission.Intent)
	}
	record, err := build(router.AdmissionOrdinary)
	if err != nil {
		return pipeline.LocalLogOutcome{}, err
	}
	outcome, err := local.pipeline.ProjectSpooled(ctx, record, emission.Obligations, emission.Known)
	if err != nil {
		return outcome, err
	}
	work, failures := outcome.OptionalWork(), outcome.OptionalFailures()
	if len(work) == 0 && len(failures) == 0 {
		return outcome, nil
	}
	dispatchValue, ok := lease.Component(DestinationDispatchComponentName)
	dispatch, typed := dispatchValue.(*destinationDispatchComponent)
	if !ok || !typed || dispatch == nil || dispatch.digest != graph.Digest() {
		return outcome, &Error{code: ErrorComponentUnavailable}
	}
	for _, failure := range failures {
		dispatch.ObserveProjectionFailure(failure)
	}
	if len(failures) != 0 {
		return outcome, errors.New("receipt destination projection failed")
	}
	// Admit the record to every destination first: one destination that
	// refuses or stalls must not hold it back from the others.
	var errs []error
	waits := make([]func(context.Context) error, 0, len(work))
	for _, item := range work {
		wait, err := dispatch.EnqueueAcknowledged(item)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		waits = append(waits, wait)
	}
	acknowledgements := make([]error, len(waits))
	var group sync.WaitGroup
	for index, wait := range waits {
		group.Go(func() { acknowledgements[index] = wait(ctx) })
	}
	group.Wait()
	return outcome, errors.Join(append(errs, acknowledgements...)...)
}
