// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"context"
	"errors"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"strings"
	"testing"
)

func TestWindowsCleanupStagePreservesCancellationAndJoinedCausesWithoutFormatting(t *testing.T) {
	for _, first := range []string{"native_handles_close", "asset_close", "startup_copies_close", "preowner_pipes_close"} {
		custody := &windowsCustody{}
		custody.markUncertain(first)
		custody.markUncertain("native_handles_close")
		if !custody.uncertain || custody.uncertaintyStage() != first {
			t.Fatal("first failed-close category was lost")
		}
	}
	unknown := &windowsCustody{}
	unknown.markUncertain("private-stage")
	if unknown.uncertaintyStage() != "sticky_uncertainty" {
		t.Fatal("unknown close category escaped")
	}
	cause := errors.Join(bridgeowner.ErrCleanup, context.DeadlineExceeded, privateStartCause{})
	for _, stage := range []string{"entry", "completion", "startup_wait", "cleanup_slot", "root_wait", "job_query", "native_signal", "native_wait", "native_handles_close", "asset_close", "startup_copies_close", "preowner_pipes_close", "pipe_setup_close", "sticky_uncertainty"} {
		err := wrapWindowsCleanupError(stage, cause)
		var classified interface{ NativeCleanupStage() string }
		if !errors.Is(err, bridgeowner.ErrCleanup) || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &classified) || classified.NativeCleanupStage() != stage {
			t.Fatal("cause or stage lost")
		}
		if len(err.Error()) > 128 || !strings.HasSuffix(err.Error(), stage) {
			t.Fatal("unbounded error")
		}
	}
	err := wrapWindowsCleanupError("private-stage", privateStartCause{})
	if strings.Contains(err.Error(), "private-stage") || err.(*windowsCleanupError).NativeCleanupStage() != "unclassified" || wrapWindowsCleanupError("entry", nil) != nil {
		t.Fatal("unknown stage or success escaped")
	}
}
