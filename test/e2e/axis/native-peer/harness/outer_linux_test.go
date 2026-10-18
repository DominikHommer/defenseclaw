// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type failReady struct{}

func (failReady) Write([]byte) (int, error) { return 0, errors.New("fixed readiness failure") }

type mustNotRead struct{ t *testing.T }

func (r mustNotRead) Read([]byte) (int, error) {
	r.t.Fatal("GRANT consumed despite failed READY")
	return 0, io.EOF
}

func TestFixedWorkerRequiresReadyThenOneExactGrant(t *testing.T) {
	for _, grant := range []string{workerGrant, "", "wrong", workerGrant + workerGrant, workerGrant + "x"} {
		var ready bytes.Buffer
		err := readyThenGrant(&ready, strings.NewReader(grant))
		if (err == nil) != (grant == workerGrant) || ready.String() != workerReady {
			t.Fatal("fixed readiness/grant contract broadened")
		}
	}
	if err := readyThenGrant(failReady{}, mustNotRead{t}); err == nil {
		t.Fatal("failed readiness admitted worker")
	}
	// No child image or namespace is created by this wire-only ordering test.
	var ready bytes.Buffer
	reader := &orderedGrant{ready: &ready, reader: strings.NewReader(workerGrant)}
	if err := readyThenGrant(&ready, reader); err != nil {
		t.Fatal(err)
	}
}

type orderedGrant struct {
	ready  *bytes.Buffer
	reader *strings.Reader
}

func (r *orderedGrant) Read(p []byte) (int, error) {
	if r.ready.String() != workerReady {
		return 0, errors.New("read before fixed readiness")
	}
	return r.reader.Read(p)
}

func TestUnreviewedWorkerRegistryRefusesBeforeNativeDescriptors(t *testing.T) {
	record, owner, err := executeWorkerWithRegistry([]string{"--receipt", "missing", "--evidence", "missing"}, reviewedRegistry{})
	if !errors.Is(err, errUnreviewed) || record["execution_performed"] != false || len(owner.pending) != 0 {
		t.Fatal("unreviewed worker reached a native capability")
	}
}

func TestOuterCustodyCompletedWaitPreferredOverCanceledContext(t *testing.T) {
	done := make(chan struct{})
	close(done)
	o := &outerCustodian{pidfd: -1, done: done, complete: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := o.stopAndWait(ctx); err != nil {
		t.Fatal(err)
	}
	pending := &outerCustodian{pidfd: -1, done: make(chan struct{}), starting: true}
	if err := pending.stopAndWait(ctx); !errors.Is(err, context.Canceled) || !pending.closed || !pending.starting {
		t.Fatal("pending kernel start lost retained cleanup state")
	}
}

func TestOuterCaptureBoundsBytesWithoutExecutingImage(t *testing.T) {
	b := &boundedCapture{}
	if _, err := b.Write(bytes.Repeat([]byte{'x'}, outputLimit)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{'y'}); err == nil {
		t.Fatal("oversized child capture accepted")
	}
	data, overflow := b.snapshot()
	if len(data) != outputLimit || !overflow {
		t.Fatal("bounded capture observation differs")
	}
}
