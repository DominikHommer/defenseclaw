// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

func syntheticRegistry(t *testing.T) reviewedRegistry {
	t.Helper()
	no := false
	v := artifactReceipt{Version: 1, Scope: harnessScope, Verified: true, ExecutionPerformed: &no, ProductionCertification: &no,
		Axis: "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c", MXC: "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2", Bubblewrap: "8e51677abd7e3338e4952370bf7d902e37d8cbb6",
		StaticClosureSHA: strings.Repeat("a", 64), PayloadSourceSHA: strings.Repeat("b", 64)}
	for _, role := range []string{"peer_and_static_bwrap", "fixed_payload"} {
		v.Builds = append(v.Builds, buildIdentity{role, strings.Repeat("c", 40), 1, 2, strings.Repeat("d", 64), strings.Repeat("e", 64)})
	}
	for i, role := range []string{"peer", "static_musl_bwrap", "fixed_payload"} {
		v.Images = append(v.Images, imageIdentity{role, []string{"images/peer", "images/bwrap-static-musl", "images/fixed-payload"}[i], strings.Repeat("f", 64), 128})
	}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return reviewedRegistry{Reviewed: true, ReceiptSHA: digestBytes(data), Receipt: v}
}

func TestDefaultAndClosedRegistryNeverAccessArtifactsOrStart(t *testing.T) {
	for _, args := range [][]string{nil, {"--run-fixed"}, {"--run-fixed", "--command", "anything"}, {"--run-fixed", "--receipt", "missing", "--evidence", "missing"}} {
		record, _, err := execute(args)
		if err == nil || record["execution_performed"] != false || record["passed"] != false {
			t.Fatal("unreviewed/default source permitted execution")
		}
	}
	if !errors.Is(liveRegistry.validate(), errUnreviewed) {
		t.Fatal("live registry must remain closed pending independent artifacts")
	}
}

func TestExactReviewedReceiptPinsCannotBeChosenByCaller(t *testing.T) {
	r := syntheticRegistry(t)
	data, _ := json.Marshal(r.Receipt)
	if _, err := admitReceipt(data, r); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"hash", "unknown", "trailing", "metadata", "unreviewed"} {
		t.Run(kind, func(t *testing.T) {
			candidate := slices.Clone(data)
			pins := r
			switch kind {
			case "hash":
				candidate = append(candidate, ' ')
			case "unknown":
				candidate = append([]byte(`{"extra":true,`), candidate[1:]...)
				pins.ReceiptSHA = digestBytes(candidate)
			case "trailing":
				candidate = append(candidate, []byte("\n{}")...)
				pins.ReceiptSHA = digestBytes(candidate)
			case "metadata":
				candidate = []byte(strings.Replace(string(candidate), `"run":1`, `"run":3`, 1))
				pins.ReceiptSHA = digestBytes(candidate)
			case "unreviewed":
				pins.Reviewed = false
			}
			if _, err := admitReceipt(candidate, pins); err == nil {
				t.Fatal("different review receipt admitted")
			}
		})
	}
}

func TestFixedPlanLiteralValuesAndNoArbitrarySelectors(t *testing.T) {
	outside := "/tmp/dc-axis-native-peer-" + strings.Repeat("a", 32) + "/outside"
	p, err := fixedPlan("argv", outside)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/.defenseclaw/payload", "argv", "", "a b", "a\"b", "tail\\", "λ-雪;$()`&|<>*?", "quoted space\\"}
	if !slices.Equal(p.Argv, want) || !p.Offline || p.Workdir != "/work" || p.Terminal != nil || p.TimeoutMS != 5000 || p.OutputLimit != outputLimit {
		t.Fatal("fixed execution plan broadened")
	}
	if !reflect.DeepEqual(p.Filesystem, bridgeproto.Filesystem{Read: []string{"/readonly"}, Write: []string{"/work", "/home", "/tmp"}, Deny: []string{}}) {
		t.Fatal("fixed guest grants changed")
	}
	if len(p.Environment) != 3 || p.Environment[2] != (bridgeproto.Variable{Name: "DC_AXIS_FIXED_PAYLOAD", Value: "fixed-private-v1"}) {
		t.Fatal("fixed environment broadened")
	}
	if _, err := fixedPlan("shell", outside); err == nil {
		t.Fatal("arbitrary command selector admitted")
	}
	for _, value := range []string{"/home/customer", outside + "/extra", strings.Replace(outside, "aaaa", "AAAA", 1)} {
		if _, err := fixedPlan("boundaries", value); err == nil {
			t.Fatal("arbitrary outside path admitted")
		}
	}
	p, err = fixedPlan("boundaries", outside)
	if err != nil || p.Argv[2] != outside {
		t.Fatal("fixed outside fixture not bound")
	}
}

type fakeOwner struct {
	binding  bridgeproto.Binding
	mode     string
	sent     []bridgeowner.Command
	frames   []bridgeproto.Frame
	sequence uint64
	mutate   func(*bridgeproto.Frame)
}

func (f *fakeOwner) emit(kind bridgeproto.Kind, request uint64, data *bridgeproto.Data, result *bridgeproto.Result) {
	f.sequence++
	frame := bridgeproto.Frame{Version: bridgeproto.Version, Sequence: f.sequence, Request: request, Binding: f.binding, Kind: kind, Data: data, Result: result}
	if f.mutate != nil {
		f.mutate(&frame)
	}
	f.frames = append(f.frames, frame)
}

func (f *fakeOwner) Send(_ context.Context, cmd bridgeowner.Command) (uint64, error) {
	f.sent = append(f.sent, cmd)
	request := uint64(len(f.sent))
	switch cmd.Kind {
	case bridgeproto.Prepare:
		f.emit(bridgeproto.Prepared, request, nil, nil)
	case bridgeproto.Launch:
		f.emit(bridgeproto.Started, request, nil, nil)
		out := map[string]string{"argv": "FIXED_NATIVE_ARGV\n", "stdio": "FIXED_NATIVE_INPUT_READY\nFIXED_NATIVE_INPUT_EOF\n", "exit23": "FIXED_NATIVE_EXIT23\n", "boundaries": "FIXED_NATIVE_BOUNDARIES\n"}[f.mode]
		// Independent output chunks must reconstruct the exact stream.
		for _, chunk := range []string{out[:3], out[3:]} {
			f.emit(bridgeproto.Output, request, &bridgeproto.Data{Stream: "stdout", Bytes: []byte(chunk)}, nil)
		}
		if f.mode == "stdio" {
			f.emit(bridgeproto.Output, request, &bridgeproto.Data{Stream: "stderr", Bytes: []byte("FIXED_NATIVE_STDERR\n")}, nil)
		}
		f.emit(bridgeproto.Exited, request, nil, &bridgeproto.Result{ExitCode: 23})
	case bridgeproto.Destroy:
		f.emit(bridgeproto.Destroyed, request, nil, nil)
	}
	return request, nil
}

func (f *fakeOwner) Receive(context.Context) (bridgeproto.Frame, error) {
	if len(f.frames) == 0 {
		return bridgeproto.Frame{}, errors.New("fake stream exhausted")
	}
	v := f.frames[0]
	f.frames = f.frames[1:]
	return v, nil
}

func TestFixedProtocolRequiresByteStreamsExitAndSeparateNativeCleanup(t *testing.T) {
	for _, mode := range fixedCases {
		t.Run(mode, func(t *testing.T) {
			plan, err := fixedPlan(mode, "/tmp/dc-axis-native-peer-"+strings.Repeat("a", 32)+"/outside")
			if err != nil {
				t.Fatal(err)
			}
			binding, err := fixedBinding("fixed-session", "fixed-held-identity", plan, syntheticRegistry(t).Receipt)
			if err != nil {
				t.Fatal(err)
			}
			owner := &fakeOwner{binding: binding, mode: mode}
			result, err := exercise(context.Background(), owner, binding, plan, mode)
			if err != nil || !result.Prepared || !result.Started || !result.PayloadMarker || !result.Destroyed || result.ExitCode != 23 || result.Passed || result.NativeCleanup {
				t.Fatalf("protocol alone must not claim native cleanup: %+v %v", result, err)
			}
			var kinds []bridgeproto.Kind
			for _, cmd := range owner.sent {
				kinds = append(kinds, cmd.Kind)
			}
			want := []bridgeproto.Kind{bridgeproto.Prepare, bridgeproto.Launch}
			if mode == "stdio" {
				want = append(want, bridgeproto.Input)
			}
			want = append(want, bridgeproto.InputEOF, bridgeproto.Wait, bridgeproto.Destroy)
			if !slices.Equal(kinds, want) {
				t.Fatal("fixed command order changed")
			}
			if mode == "stdio" && string(owner.sent[2].Data.Bytes) != fixedInput {
				t.Fatal("binary input or EOF bytes changed")
			}
			caseError(&result, errors.New("native cleanup failed"))
			if result.Passed {
				t.Fatal("protocol success hid native cleanup failure")
			}
		})
	}
}

func TestUnexpectedBindingExitTruncationOrBytesRefuse(t *testing.T) {
	plan, _ := fixedPlan("exit23", "")
	binding, _ := fixedBinding("fixed-session", "held-id", plan, syntheticRegistry(t).Receipt)
	for _, kind := range []string{"binding", "request", "exit", "timeout", "truncated", "bytes", "failure"} {
		t.Run(kind, func(t *testing.T) {
			owner := &fakeOwner{binding: binding, mode: "exit23", mutate: func(f *bridgeproto.Frame) {
				if f.Kind == bridgeproto.Output && kind == "bytes" {
					f.Data.Bytes = []byte("wrong fixed bytes")
				}
				if f.Kind != bridgeproto.Exited {
					return
				}
				switch kind {
				case "binding":
					f.Binding.PolicyDigest = "sha256:" + strings.Repeat("0", 64)
				case "request":
					f.Request = 99
				case "exit":
					f.Result.ExitCode = 0
				case "timeout":
					f.Result.TimedOut = true
				case "truncated":
					f.Result.Truncated = true
				case "failure":
					f.Kind = bridgeproto.Failed
					f.Result = nil
					f.Failure = &bridgeproto.Failure{Code: "launch_failed"}
				}
			}}
			if _, err := exercise(context.Background(), owner, binding, plan, "exit23"); err == nil {
				t.Fatal("bad fixed result admitted")
			}
		})
	}
}
