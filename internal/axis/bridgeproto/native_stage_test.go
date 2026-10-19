// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeproto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNativePreparationStageIsClosedDiagnosticAndAbsencePreservesBytes(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	frame := Frame{Version: Version, Sequence: 1, Request: 1, Binding: Binding{SessionID: "fixed", SessionDigest: hash, PolicyDigest: hash, RuntimeDigest: hash, HarnessDigest: hash, PreparationHash: hash}, Kind: Failed, Failure: &Failure{Code: "preparation_failed"}}
	absent, err := json.Marshal(frame)
	if err != nil || bytes.Contains(absent, []byte("native_stage")) {
		t.Fatal("absent diagnostic changed legacy bytes")
	}
	if parsed, err := Parse(absent); err != nil || parsed.Failure.NativeStage != nil {
		t.Fatal("legacy failure refused")
	}
	for _, stage := range []string{"windows_capability_binding", "windows_capability_objects", "windows_payload_access", "windows_cwd_privacy", "windows_grant_pin", "windows_payload_custody"} {
		value := NativePreparationStage(stage)
		frame.Failure.NativeStage = &value
		raw, err := json.Marshal(frame)
		if err != nil {
			t.Fatal("marshal")
		}
		if parsed, err := Parse(raw); err != nil || parsed.Failure.NativeStage == nil || string(*parsed.Failure.NativeStage) != stage {
			t.Fatal("closed diagnostic refused")
		}
		for _, code := range []string{"invalid_request", "unsupported", "launch_failed", "io_failed", "cleanup_failed"} {
			changed := bytes.Replace(raw, []byte(`"code":"preparation_failed"`), []byte(`"code":"`+code+`"`), 1)
			if _, err := Parse(changed); err == nil {
				t.Fatal("stage on nonpreparation failure admitted")
			}
		}
	}
	private := NativePreparationStage("private-path-value")
	frame.Failure.NativeStage = &private
	raw, _ := json.Marshal(frame)
	if _, err := Parse(raw); err == nil {
		t.Fatal("unrecognized diagnostic admitted")
	}
}
