// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

const sentinel = "fixed-public-native-peer-canary\n"
const fixedInput = "fixed-public-input\x00\xff\n"
const outputLimit = 64 << 10

var fixedCases = []string{"argv", "stdio", "exit23", "boundaries"}

func fixedPlan(mode, outside string) (bridgeproto.Preparation, error) {
	plan := bridgeproto.Preparation{Backend: "bubblewrap", Argv: []string{"/.defenseclaw/payload", mode},
		Environment: []bridgeproto.Variable{{Name: "HOME", Value: "/home"}, {Name: "TMPDIR", Value: "/tmp"}, {Name: "DC_AXIS_FIXED_PAYLOAD", Value: "fixed-private-v1"}},
		Workdir:     "/work", Filesystem: bridgeproto.Filesystem{Read: []string{"/readonly"}, Write: []string{"/work", "/home", "/tmp"}, Deny: []string{}},
		Offline: true, TimeoutMS: 5000, OutputLimit: outputLimit}
	switch mode {
	case "argv":
		plan.Argv = append(plan.Argv, "", "a b", "a\"b", "tail\\", "λ-雪;$()`&|<>*?", "quoted space\\")
	case "boundaries":
		if !fixedOutside(outside) {
			return plan, errors.New("invalid fixed outside fixture identity")
		}
		plan.Argv = append(plan.Argv, outside)
	case "stdio", "exit23":
	default:
		return plan, errors.New("unknown contributor case")
	}
	return plan, plan.Validate()
}

func fixedOutside(value string) bool {
	const prefix, suffix = "/tmp/dc-axis-native-peer-", "/outside"
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

// Digests correlate this fixed contributor experiment only. They are neither
// a production ExecutionPolicy nor a translated PolicyReceipt/capability claim.
func fixedBinding(session, fixtureIdentity string, plan bridgeproto.Preparation, receipt artifactReceipt) (bridgeproto.Binding, error) {
	if len(receipt.Images) != 3 {
		return bridgeproto.Binding{}, errors.New("fixed artifact identity missing")
	}
	preparation, err := bridgeproto.PreparationDigest(plan)
	if err != nil {
		return bridgeproto.Binding{}, err
	}
	artifacts, err := json.Marshal(receipt)
	if err != nil {
		return bridgeproto.Binding{}, err
	}
	policy := "sha256:" + digestBytes([]byte(harnessScope+"\x00strict-sparse-readonly-root-offline-no-broker-no-hooks\x00"+preparation))
	runtime := "sha256:" + digestBytes(artifacts)
	harness := "sha256:" + receipt.Images[2].SHA
	full := session + "\x00" + fixtureIdentity + "\x00" + policy + "\x00" + runtime + "\x00" + harness
	b := bridgeproto.Binding{SessionID: session, SessionDigest: "sha256:" + digestBytes([]byte(full)), PolicyDigest: policy, RuntimeDigest: runtime, HarnessDigest: harness, PreparationHash: preparation}
	return b, b.Validate()
}

type protocolOwner interface {
	Send(context.Context, bridgeowner.Command) (uint64, error)
	Receive(context.Context) (bridgeproto.Frame, error)
}

type caseResult struct {
	Mode          string `json:"mode"`
	Passed        bool   `json:"passed"`
	Prepared      bool   `json:"prepared"`
	Started       bool   `json:"started"`
	PayloadMarker bool   `json:"fixed_payload_marker_observed"`
	ExitCode      int32  `json:"exit_code"`
	Destroyed     bool   `json:"destroyed"`
	NativeCleanup bool   `json:"native_cleanup_observed"`
	OutputBytes   int    `json:"output_bytes"`
	StderrBytes   int    `json:"stderr_bytes"`
	Error         string `json:"error,omitempty"`
	ProtocolStage string `json:"protocol_stage,omitempty"`
	PeerFailure   string `json:"peer_failure,omitempty"`
}

type fixedPeerFailure string

func (e fixedPeerFailure) Error() string { return string(e) }

func expectReply(ctx context.Context, owner protocolOwner, binding bridgeproto.Binding, request uint64, kind bridgeproto.Kind) error {
	frame, err := owner.Receive(ctx)
	if err != nil {
		return err
	}
	if frame.Validate() == nil && frame.Binding == binding && frame.Request == request && frame.Kind == bridgeproto.Failed {
		return fixedPeerFailure(frame.Failure.Code)
	}
	if frame.Validate() != nil || frame.Binding != binding || frame.Request != request || frame.Kind != kind {
		return errors.New("fixed protocol reply or binding differed")
	}
	return nil
}

func exercise(ctx context.Context, owner protocolOwner, binding bridgeproto.Binding, plan bridgeproto.Preparation, mode string) (result caseResult, resultErr error) {
	result.Mode = mode
	defer func() {
		var failure fixedPeerFailure
		if errors.As(resultErr, &failure) {
			result.PeerFailure = string(failure)
		}
	}()
	result.ProtocolStage = "prepare_send"
	prepare, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Prepare, Plan: &plan})
	if err != nil {
		return result, err
	}
	result.ProtocolStage = "prepare_reply"
	if err := expectReply(ctx, owner, binding, prepare, bridgeproto.Prepared); err != nil {
		return result, err
	}
	result.Prepared = true
	result.ProtocolStage = "launch_send"
	launch, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Launch})
	if err != nil {
		return result, err
	}
	result.ProtocolStage = "launch_reply"
	if err := expectReply(ctx, owner, binding, launch, bridgeproto.Started); err != nil {
		return result, err
	}
	result.Started = true
	result.ProtocolStage = "input_and_wait"
	if mode == "stdio" {
		if _, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Input, Data: &bridgeproto.Data{Stream: "stdin", Bytes: []byte(fixedInput)}}); err != nil {
			return result, err
		}
	}
	if _, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.InputEOF}); err != nil {
		return result, err
	}
	if _, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Wait}); err != nil {
		return result, err
	}
	result.ProtocolStage = "output_and_exit"
	var stdout, stderr bytes.Buffer
	exited := false
	for count := 0; count < 256; count++ {
		frame, err := owner.Receive(ctx)
		if err != nil {
			return result, err
		}
		if frame.Validate() != nil || frame.Binding != binding || frame.Request != launch {
			return result, errors.New("fixed output/result binding differed")
		}
		switch frame.Kind {
		case bridgeproto.Output:
			if stdout.Len()+stderr.Len()+len(frame.Data.Bytes) > outputLimit {
				return result, errors.New("fixed output exceeded aggregate bound")
			}
			if frame.Data.Stream == "stdout" {
				_, _ = stdout.Write(frame.Data.Bytes)
			} else {
				_, _ = stderr.Write(frame.Data.Bytes)
			}
		case bridgeproto.Failed:
			return result, fixedPeerFailure(frame.Failure.Code)
		case bridgeproto.Exited:
			result.ExitCode = frame.Result.ExitCode
			if frame.Result.ExitCode != 23 || frame.Result.TimedOut || frame.Result.Truncated {
				return result, errors.New("fixed exit/timeout/truncation differed")
			}
			exited = true
		default:
			return result, errors.New("unexpected fixed execution event")
		}
		if exited {
			break
		}
	}
	if !exited {
		return result, errors.New("fixed event count exceeded")
	}
	result.OutputBytes, result.StderrBytes = stdout.Len(), stderr.Len()
	want, wantErr := map[string]string{"argv": "FIXED_NATIVE_ARGV\n", "stdio": "FIXED_NATIVE_INPUT_READY\nFIXED_NATIVE_INPUT_EOF\n", "exit23": "FIXED_NATIVE_EXIT23\n", "boundaries": "FIXED_NATIVE_BOUNDARIES\n"}[mode], ""
	if mode == "stdio" {
		wantErr = "FIXED_NATIVE_STDERR\n"
	}
	if stdout.String() != want || stderr.String() != wantErr {
		return result, errors.New("fixed byte streams differed")
	}
	result.PayloadMarker = true
	result.ProtocolStage = "destroy"
	destroy, err := owner.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Destroy})
	if err != nil {
		return result, err
	}
	if err := expectReply(ctx, owner, binding, destroy, bridgeproto.Destroyed); err != nil {
		return result, err
	}
	result.Destroyed = true
	result.ProtocolStage = "complete"
	return result, nil // native Close success remains independently mandatory
}

func caseError(result *caseResult, err error) {
	result.Passed = err == nil && result.NativeCleanup
	if err != nil {
		result.Error = fmt.Sprintf("fixed_%s_failed", result.Mode)
	}
}
