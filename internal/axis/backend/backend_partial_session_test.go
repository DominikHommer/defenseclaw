// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
)

func TestActualCallsPartialSessionDoesNotClaimCleanup(t *testing.T) {
	closeSession := actualCalls().close
	if observation := closeSession(context.Background(), nil); observation.complete || !errors.Is(observation.err, ErrSession) {
		t.Fatalf("nil session admitted cleanup: %+v", observation)
	}
	// A nonnil Session with no protocol owner and no native custody is not a
	// completed cleanup. Its own retained-custody check supplies the refusal.
	if observation := closeSession(context.Background(), &bridgeprocess.Session{}); observation.complete || !errors.Is(observation.err, bridgeprocess.ErrAdmission) {
		t.Fatalf("empty partial session admitted cleanup: %+v", observation)
	}
}

func TestObserveCleanupWithoutProtocolPreservesNativeRetryAndExpiry(t *testing.T) {
	firstFailure := errors.New("fixed native wait failure")
	calls := 0
	waitNative := func(context.Context) error {
		calls++
		if calls == 1 {
			return firstFailure
		}
		return nil
	}
	ctx := context.Background()
	first := observeCleanup(ctx, nil, waitNative)
	if first.complete || !errors.Is(first.err, firstFailure) || calls != 1 {
		t.Fatalf("lost first native failure: observation=%+v calls=%d", first, calls)
	}
	second := observeCleanup(ctx, nil, waitNative)
	if !second.complete || second.err != nil || calls != 2 {
		t.Fatalf("lost exact native retry: observation=%+v calls=%d", second, calls)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	expired := observeCleanup(canceled, nil, waitNative)
	if expired.complete || !errors.Is(expired.err, context.Canceled) || calls != 3 {
		t.Fatalf("expired context relabeled cleanup: observation=%+v calls=%d", expired, calls)
	}
}
