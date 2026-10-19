// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
)

type fakeClosedNativeSignals struct {
	stage string
}

func (fakeClosedNativeSignals) Error() string                      { panic("raw native cause must never be formatted") }
func (failure fakeClosedNativeSignals) NativeCleanupStage() string { return failure.stage }
func (fakeClosedNativeSignals) NativeCleanupSignals() bridgeprocess.WindowsNativeSignalResult {
	return bridgeprocess.WindowsNativeSignalResult{JobAttempted: true, JobFailed: true, JobWin32: 5,
		RootAttempted: true, RootFailed: true, RootWin32: 87}
}

func TestFixedNativeSignalDiagnosticRetainsBothClosedRolesOnlyAtSignalStage(t *testing.T) {
	for _, stage := range []string{"native_signal", "job_query"} {
		var output bytes.Buffer
		writeFixedDiagnostic(&output, "session_stop_and_wait", fakeClosedNativeSignals{stage: stage})
		var record struct {
			CleanupStage string                                   `json:"native_cleanup_stage"`
			Signals      *bridgeprocess.WindowsNativeSignalResult `json:"native_cleanup_signals"`
		}
		if output.Len() > 1024 || json.Unmarshal(output.Bytes(), &record) != nil || record.CleanupStage != stage {
			t.Fatal("fixed diagnostic was not bounded and closed")
		}
		if stage == "native_signal" {
			if record.Signals == nil || !record.Signals.JobFailed || record.Signals.JobWin32 != 5 ||
				!record.Signals.RootFailed || record.Signals.RootWin32 != 87 {
				t.Fatal("both signal roles were not preserved")
			}
		} else if record.Signals != nil {
			t.Fatal("signal details escaped an unrelated cleanup stage")
		}
	}
}
