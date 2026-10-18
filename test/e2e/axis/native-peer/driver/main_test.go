// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestUnreviewedDriverRefusesBeforeAnyNativeOrFilesystemWork(t *testing.T) {
	for _, args := range [][]string{nil, {"--run-fixed", "--receipt", "missing", "--evidence", "missing"}} {
		record, owner, err := execute(args, wrapperAdmission{}, func(context.Context, options, wrapperAdmission, map[string]any, *cleanupOwner) error {
			t.Fatal("closed test admission reached native driver")
			return nil
		})
		if !errors.Is(err, errUnreviewed) || record["execution_performed"] != false || len(owner.pending) != 0 {
			t.Fatal("closed test admission performed work")
		}
	}
}

func TestReviewedAdmissionUsesInjectedFakeRunnerOnly(t *testing.T) {
	admission := wrapperAdmission{Reviewed: true, SHA: strings.Repeat("a", 64), Size: 128}
	expected := errors.New("fixed fake native owner")
	calls := 0
	fake := func(ctx context.Context, opts options, got wrapperAdmission, record map[string]any, owner *cleanupOwner) error {
		calls++
		if _, ok := ctx.Deadline(); !ok || opts.receipt != "missing" || opts.evidence != "missing" || got != admission || owner == nil || record["execution_performed"] != false {
			t.Fatal("fixed metadata changed")
		}
		return expected
	}
	_, _, err := execute([]string{"--run-fixed", "--receipt", "missing", "--evidence", "missing"}, admission, fake)
	if !errors.Is(err, expected) || calls != 1 {
		t.Fatal("fake driver dispatch differed")
	}
	for _, args := range [][]string{nil, {"--run-fixed", "--binary", "anything"}, {"--run-fixed", "--receipt", "missing", "--evidence", "missing", "extra"}} {
		if _, _, err := execute(args, admission, fake); err == nil || calls != 1 {
			t.Fatal("arbitrary driver inputs admitted")
		}
	}
}
