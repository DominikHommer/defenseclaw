// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"strings"
	"syscall"
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

func TestWindowsNativeSignalDiagnosticKeepsBothRolesAndNeverFormatsCauses(t *testing.T) {
	jobErr, rootErr := syscall.Errno(5), syscall.Errno(87)
	signals := closedWindowsNativeSignals(jobErr, rootErr, true)
	if !signals.JobAttempted || !signals.JobFailed || signals.JobWin32 != 5 ||
		!signals.RootAttempted || !signals.RootFailed || signals.RootWin32 != 87 {
		t.Fatal("both attempted native failures must remain distinct")
	}
	joined := errors.Join(bridgeowner.ErrCleanup, jobErr, rootErr, privateStartCause{})
	wrapped := &windowsCleanupError{stage: "native_signal", cause: joined, signals: signals}
	var diagnostic interface {
		NativeCleanupSignals() WindowsNativeSignalResult
	}
	if !errors.Is(wrapped, bridgeowner.ErrCleanup) || !errors.Is(wrapped, jobErr) ||
		!errors.Is(wrapped, rootErr) || !errors.As(wrapped, &diagnostic) ||
		diagnostic.NativeCleanupSignals() != signals {
		t.Fatal("both native causes or closed diagnostic were lost")
	}
	if wrapped.Error() != "private AXIS native cleanup refused at native_signal" {
		t.Fatal("private cause escaped the closed wrapper")
	}
	raw, err := json.Marshal(diagnostic.NativeCleanupSignals())
	if err != nil || strings.Contains(string(raw), "private") || len(raw) > 180 {
		t.Fatal("closed signal record escaped its bound")
	}
	unknown := closedWindowsNativeSignals(privateStartCause{}, nil, false)
	if !unknown.JobAttempted || !unknown.JobFailed || unknown.JobWin32 != 0 || unknown.RootAttempted || unknown.RootFailed || unknown.RootWin32 != 0 {
		t.Fatal("unknown native status must not become a success or invented code")
	}
	jobSucceeded := closedWindowsNativeSignals(nil, syscall.Errno(5), true)
	if !jobSucceeded.JobAttempted || jobSucceeded.JobFailed || jobSucceeded.JobWin32 != 0 ||
		!jobSucceeded.RootAttempted || !jobSucceeded.RootFailed || jobSucceeded.RootWin32 != 5 {
		t.Fatal("successful Job termination and failed root termination were conflated")
	}
	rootAlreadyDone := closedWindowsNativeSignals(syscall.Errno(87), nil, false)
	if !rootAlreadyDone.JobFailed || rootAlreadyDone.JobWin32 != 87 ||
		rootAlreadyDone.RootAttempted || rootAlreadyDone.RootFailed || rootAlreadyDone.RootWin32 != 0 {
		t.Fatal("an unattempted root termination was reported")
	}
	if (&windowsCleanupError{stage: "job_query", signals: signals}).NativeCleanupSignals() != (WindowsNativeSignalResult{}) ||
		(*windowsCleanupError)(nil).NativeCleanupSignals() != (WindowsNativeSignalResult{}) {
		t.Fatal("signal facts escaped another stage")
	}
}
