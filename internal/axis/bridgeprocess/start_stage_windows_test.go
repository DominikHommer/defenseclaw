// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type privateStartCause struct{}

func (privateStartCause) Error() string { panic("cause text must never be formatted") }

func TestWindowsStartStageWrapperIsClosedAndPreservesJoinedCauses(t *testing.T) {
	private := privateStartCause{}
	cause := errors.Join(ErrAdmission, context.DeadlineExceeded, private)
	for _, stage := range []string{"allocated", "peer_duplicate", "peer_application", "payload_duplicate", "payload_metadata", "asset_cwd", "asset_read", "asset_write", "cwd_coverage", "private_pipe", "inheritable_capabilities", "bootstrap", "inheritable_stdio", "job_create", "job_limits", "protocol", "begin"} {
		err := wrapWindowsStartError(stage, cause)
		var diagnostic interface{ NativeStartStage() string }
		if !errors.Is(err, ErrAdmission) || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &diagnostic) || diagnostic.NativeStartStage() != stage {
			t.Fatal("stage wrapper lost original error authority")
		}
		if text := err.Error(); !strings.HasSuffix(text, stage) || len(text) > 128 {
			t.Fatal("unbounded stage wrapper")
		}
	}
	unknown := wrapWindowsStartError("private-value-not-a-stage", private)
	if strings.Contains(unknown.Error(), "private-value") || unknown.(*windowsStartError).NativeStartStage() != "unclassified" {
		t.Fatal("raw stage escaped")
	}
	if wrapWindowsStartError("begin", nil) != nil {
		t.Fatal("success was wrapped")
	}
}
