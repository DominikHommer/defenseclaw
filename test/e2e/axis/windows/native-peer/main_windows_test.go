// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

type fakeProtocol struct {
	commands []bridgeowner.Command
	frames   []bridgeproto.Frame
	next     uint64
}

func (f *fakeProtocol) Send(_ context.Context, command bridgeowner.Command) (uint64, error) {
	f.next++
	f.commands = append(f.commands, command)
	return f.next, nil
}
func (f *fakeProtocol) Receive(context.Context) (bridgeproto.Frame, error) {
	if len(f.frames) == 0 {
		return bridgeproto.Frame{}, errors.New("empty")
	}
	frame := f.frames[0]
	f.frames = f.frames[1:]
	return frame, nil
}

func fakeConversation() (*fakeProtocol, bridgeproto.Binding, bridgeproto.Preparation) {
	h := "sha256:" + strings.Repeat("a", 64)
	b := bridgeproto.Binding{SessionID: "fixed-test", SessionDigest: h, PolicyDigest: h, RuntimeDigest: h, HarnessDigest: h, PreparationHash: h}
	plan := fixedPlan(`C:\fixed\windows-native-peer-canary-07\fixture\work`, `C:\Windows`)
	f := &fakeProtocol{frames: []bridgeproto.Frame{
		{Kind: bridgeproto.Prepared, Request: 1}, {Kind: bridgeproto.Started, Request: 2},
		{Kind: bridgeproto.Output, Request: 2, Data: &bridgeproto.Data{Stream: "stdout", Bytes: []byte(fixedStdout)}},
		{Kind: bridgeproto.Output, Request: 2, Data: &bridgeproto.Data{Stream: "stderr", Bytes: []byte(fixedStderr)}},
		{Kind: bridgeproto.Exited, Request: 2, Result: &bridgeproto.Result{ExitCode: 23}},
		{Kind: bridgeproto.Destroyed, Request: 6},
	}}
	for i := range f.frames {
		f.frames[i].Version = bridgeproto.Version
		f.frames[i].Sequence = uint64(i + 1)
		f.frames[i].Binding = b
	}
	return f, b, plan
}

func TestFixedCanaryProtocolRequiresExactStreamsExitBindingAndDestroy(t *testing.T) {
	f, b, plan := fakeConversation()
	var record result
	if err := exercise(context.Background(), f, b, plan, []byte("public-test"), &record); err != nil || !record.Prepared || !record.PeerStartedReply || !record.CanaryMarker || !record.Exit23 || !record.Destroyed {
		t.Fatal("fixed fake conversation refused")
	}
	for _, alter := range []func(*fakeProtocol){
		func(f *fakeProtocol) { f.frames[2].Data.Bytes = []byte("different") },
		func(f *fakeProtocol) { f.frames[4].Result.ExitCode = 0 },
		func(f *fakeProtocol) { f.frames[4].Result.TimedOut = true },
		func(f *fakeProtocol) { f.frames[4].Result.Truncated = true },
		func(f *fakeProtocol) { f.frames[4].Binding.SessionID = "different" },
		func(f *fakeProtocol) { f.frames = f.frames[:5] },
	} {
		f, b, plan = fakeConversation()
		alter(f)
		record = result{}
		if exercise(context.Background(), f, b, plan, nil, &record) == nil {
			t.Fatal("altered fixed conversation admitted")
		}
	}
}

func TestFixedCanaryRegistryIsClosedAndWindowsPlanIsExplicit(t *testing.T) {
	if reviewed.valid() || (artifactRegistry{Enabled: true}).valid() {
		t.Fatal("unreviewed artifact admitted")
	}
	plan := fixedPlan(`C:\fixed\windows-native-peer-canary-07\fixture\work`, `C:\Windows`)
	if plan.Validate() != nil || plan.Backend != "windows_psec" || !plan.Offline || plan.Terminal != nil || len(plan.Environment) != 8 || len(plan.Filesystem.Read) != 1 || len(plan.Filesystem.Write) != 3 || len(plan.Filesystem.Deny) != 0 {
		t.Fatal("fixed plan differs")
	}
	if len(inputFrame(plan.Workdir, `C:\Windows`, 12345, 23456)) > bridgeproto.MaxDataBytes {
		t.Fatal("fixed input exceeds one frame")
	}
}

type privateDiagnosticError struct{}

func (privateDiagnosticError) Error() string { panic("error text must never be formatted") }

func TestFixedFailureDiagnosticsPreserveJoinedClassesAndNeverFormatRawErrors(t *testing.T) {
	var output bytes.Buffer
	err := errors.Join(bridgeowner.ErrCleanup, context.DeadlineExceeded,
		&os.PathError{Op: "private-operation", Path: "private-path-value", Err: syscall.Errno(5)})
	writeFixedDiagnostic(&output, "start", err)
	for _, want := range []string{`"fixed_diagnostic_stage":"start"`, `"owner_cleanup"`, `"context_deadline"`, `"win32_error":5`} {
		if !strings.Contains(output.String(), want) {
			t.Fatal("missing bounded failure fact")
		}
	}
	if strings.Contains(output.String(), "private-") || output.Len() > 1024 {
		t.Fatal("raw or unbounded diagnostic")
	}
	output.Reset()
	writeFixedDiagnostic(&output, "not-a-stage", privateDiagnosticError{})
	if !strings.Contains(output.String(), `"fixed_diagnostic_stage":"diagnostic_refused"`) || !strings.Contains(output.String(), `"unclassified_error":true`) {
		t.Fatal("unclassified failure did not stay closed")
	}
}

type stagedDiagnosticError struct{ stage string }

func (stagedDiagnosticError) Error() string                { panic("stage error text must never be formatted") }
func (err stagedDiagnosticError) NativeStartStage() string { return err.stage }

func TestFixedFailureDiagnosticRefusesUnrecognizedNativeStartStages(t *testing.T) {
	for _, item := range []struct{ stage, want string }{{"asset_read", "asset_read"}, {"private-stage-value", "unclassified"}} {
		var output bytes.Buffer
		writeFixedDiagnostic(&output, "start", errors.Join(bridgeprocess.ErrAdmission, stagedDiagnosticError{item.stage}))
		if !strings.Contains(output.String(), `"native_start_stage":"`+item.want+`"`) || strings.Contains(output.String(), "private-stage-value") {
			t.Fatal("native stage was not closed")
		}
	}
}

func TestFixedProtocolFailureDiagnosticsRequireValidatedCorrelationAndRedactCauses(t *testing.T) {
	for _, code := range []string{"invalid_request", "unsupported", "preparation_failed", "launch_failed", "io_failed", "cleanup_failed"} {
		f, binding, plan := fakeConversation()
		f.frames[0].Kind = bridgeproto.Failed
		f.frames[0].Failure = &bridgeproto.Failure{Code: code}
		var record result
		err := exercise(context.Background(), f, binding, plan, nil, &record)
		if err == nil || record.Prepared || len(f.commands) != 1 {
			t.Fatal("failed Prepare was admitted or later commands sent")
		}
		var output bytes.Buffer
		writeFixedDiagnostic(&output, "protocol", err)
		for _, want := range []string{`"protocol_operation":"prepare_receive"`, `"peer_frame_kind":"failed"`, `"peer_failure_code":"` + code + `"`} {
			if !strings.Contains(output.String(), want) {
				t.Fatal("missing validated closed failure fact")
			}
		}
	}
	for _, mutate := range []func(*bridgeproto.Frame){
		func(frame *bridgeproto.Frame) { frame.Binding.SessionID = "wrong-binding" },
		func(frame *bridgeproto.Frame) { frame.Request++ },
		func(frame *bridgeproto.Frame) { frame.Failure.Code = "private-value" },
	} {
		f, binding, _ := fakeConversation()
		f.frames[0].Kind = bridgeproto.Failed
		f.frames[0].Failure = &bridgeproto.Failure{Code: "preparation_failed"}
		mutate(&f.frames[0])
		err := reply(context.Background(), f, binding, 1, bridgeproto.Prepared, "prepare_receive")
		var output bytes.Buffer
		writeFixedDiagnostic(&output, "protocol", err)
		if err == nil || strings.Contains(output.String(), "peer_failure_code") || strings.Contains(output.String(), "private-value") || strings.Contains(output.String(), "peer_frame_kind") {
			t.Fatal("invalid or uncorrelated peer fields escaped")
		}
	}
	for _, item := range []struct{ operation, kind, failure string }{
		{"prepare_send", "", ""},
		{"private-operation", "private-kind", "private-failure"},
	} {
		err := &fixedProtocolError{operation: item.operation, kind: bridgeproto.Kind(item.kind), failure: item.failure, cause: privateDiagnosticError{}}
		var output bytes.Buffer
		writeFixedDiagnostic(&output, "protocol", err)
		if output.Len() > 1024 || strings.Contains(output.String(), "private-") {
			t.Fatal("raw protocol diagnostic escaped")
		}
	}
}

func TestFixedPreparationDiagnosticRequiresCorrelatedValidatedFailure(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		f, binding, _ := fakeConversation()
		f.frames[0].Kind = bridgeproto.Failed
		stage := bridgeproto.NativePreparationStage("windows_cwd_privacy")
		f.frames[0].Failure = &bridgeproto.Failure{Code: "preparation_failed", NativeStage: &stage}
		if wrong {
			f.frames[0].Request++
		}
		err := reply(context.Background(), f, binding, 1, bridgeproto.Prepared, "prepare_receive")
		var output bytes.Buffer
		writeFixedDiagnostic(&output, "protocol", err)
		if err == nil || strings.Contains(output.String(), "windows_cwd_privacy") == wrong {
			t.Fatal("uncorrelated or missing stage")
		}
	}
	var output bytes.Buffer
	writeFixedDiagnostic(&output, "protocol", &fixedProtocolError{operation: "prepare_receive", preparationStage: "private-stage", cause: privateDiagnosticError{}})
	if strings.Contains(output.String(), "private-stage") {
		t.Fatal("unknown stage escaped")
	}
}
