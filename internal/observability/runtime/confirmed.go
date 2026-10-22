// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// EmitConfirmed is for replayable lifecycle receipts, off the hook path. A
// producer may retire its durable spool item only after local persistence
// and every selected destination has acknowledged delivery. Replays reuse
// the producer's stable occurrence ID and do not insert another local row.
func (runtime *Runtime) EmitConfirmed(ctx context.Context, metadata router.Metadata, builder EmitBuilder, replay bool) (pipeline.LocalLogOutcome, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || builder == nil {
		return pipeline.LocalLogOutcome{}, &Error{code: ErrorInvalidDependency}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return pipeline.LocalLogOutcome{}, err
	}
	defer lease.Release()
	graph := lease.Graph()
	value, ok := lease.Component(LocalLogComponentName)
	local, typed := value.(*localLogComponent)
	if graph == nil || !ok || !typed || local == nil || local.digest != graph.Digest() {
		return pipeline.LocalLogOutcome{}, &Error{code: ErrorComponentUnavailable}
	}
	build := leaseRecordBuilder(ctx, lease, EmitContext{plan: graph.Plan(), digest: graph.Digest(), generation: graph.Generation()}, builder, false)
	var outcome pipeline.LocalLogOutcome
	if replay {
		record, buildErr := build(router.AdmissionOrdinary)
		if buildErr != nil {
			return outcome, buildErr
		}
		outcome = local.pipeline.ProjectCommitted(ctx, record)
	} else {
		var processErr error
		outcome, processErr = local.Process(ctx, metadata, build)
		if processErr != nil {
			return outcome, processErr
		}
	}
	if !outcome.LocalPersisted() {
		return outcome, errors.New("receipt local persistence is unconfirmed")
	}
	dispatchValue, ok := lease.Component(DestinationDispatchComponentName)
	dispatch, typed := dispatchValue.(*destinationDispatchComponent)
	if !ok || !typed || dispatch == nil || dispatch.digest != graph.Digest() {
		return outcome, &Error{code: ErrorComponentUnavailable}
	}
	for _, failure := range outcome.OptionalFailures() {
		dispatch.ObserveProjectionFailure(failure)
	}
	if len(outcome.OptionalFailures()) != 0 {
		return outcome, errors.New("receipt destination projection failed")
	}
	for _, work := range outcome.OptionalWork() {
		if err := dispatch.EnqueueConfirmed(ctx, work); err != nil {
			return outcome, err
		}
	}
	return outcome, nil
}
