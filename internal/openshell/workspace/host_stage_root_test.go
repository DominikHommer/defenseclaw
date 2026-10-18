// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// These tests use opaque inert File values and replace their closer before
// release. They perform no native file operation, namespace or process action.
func inertHostStageRoot(t *testing.T) (*HostStage, *int) {
	t.Helper()
	cleaned := new(int)
	return &HostStage{
		duplicateRoot: func() (*os.File, error) { return new(os.File), nil },
		close:         func() error { *cleaned++; return nil },
	}, cleaned
}

func inertHostStageLease(t *testing.T, stage *HostStage) *RootLease {
	t.Helper()
	lease, err := stage.AcquireRoot()
	if err != nil {
		t.Fatal(err)
	}
	lease.closeFile = func() error { return nil }
	return lease
}

func requireHostStageInUse(t *testing.T, stage *HostStage) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- stage.Close() }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrHostStageInUse) {
			t.Fatalf("close with retained consumer custody: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stage close waited for consumer native I/O")
	}
}

func TestHostStageRootLeaseCloseBarrierWithInertHandles(t *testing.T) {
	stage, cleaned := inertHostStageRoot(t)
	lease := inertHostStageLease(t, stage)
	if file, err := lease.File(); file == nil || err != nil {
		t.Fatalf("borrow admitted inert capability: %v", err)
	}
	requireHostStageInUse(t, stage)
	if *cleaned != 0 {
		t.Fatal("cleanup began while a consumer was active")
	}
	if _, err := stage.AcquireRoot(); err == nil {
		t.Fatal("new acquisition survived a close request")
	}
	if _, err := stage.TreePath(); err == nil {
		t.Fatal("display path survived a close request")
	}
	if _, err := lease.File(); err == nil {
		t.Fatal("new borrow survived a close request")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil || *cleaned != 0 {
		t.Fatal("lease release was not idempotent or implicitly cleaned the stage")
	}
	if err := stage.Close(); err != nil || *cleaned != 1 {
		t.Fatalf("explicit cleanup retry: %v, calls=%d", err, *cleaned)
	}
	if err := stage.Close(); err != nil || *cleaned != 1 {
		t.Fatal("stage cleanup repeated")
	}
}

func TestHostStageRootLeaseCloseFailureRetainsOwner(t *testing.T) {
	stage, cleaned := inertHostStageRoot(t)
	lease := inertHostStageLease(t, stage)
	failure := errors.New("fixed native close uncertainty")
	count := 0
	lease.closeFile = func() error { count++; return failure }
	for range 2 {
		if !errors.Is(lease.Close(), failure) {
			t.Fatal("uncertain close was erased")
		}
	}
	if count != 1 || len(stage.rootLeases) != 1 {
		t.Fatal("uncertain close was retried or its custody released")
	}
	if file, err := lease.File(); file != nil || !errors.Is(err, failure) {
		t.Fatal("uncertain capability remained borrowable")
	}
	if err := stage.Close(); !errors.Is(err, ErrHostStageInUse) || !errors.Is(err, failure) || *cleaned != 0 {
		t.Fatalf("stage discarded close uncertainty: %v", err)
	}
}

func TestHostStageRootLeasePendingAcquisitionBlocksCleanup(t *testing.T) {
	stage, cleaned := inertHostStageRoot(t)
	entered, finish := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(finish) })
	defer release()
	stage.duplicateRoot = func() (*os.File, error) {
		close(entered)
		<-finish
		return new(os.File), nil
	}
	type answer struct {
		lease *RootLease
		err   error
	}
	done := make(chan answer, 1)
	go func() { lease, err := stage.AcquireRoot(); done <- answer{lease, err} }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("root acquisition did not reach the inert duplicator")
	}
	requireHostStageInUse(t, stage)
	if *cleaned != 0 {
		t.Fatal("pending acquisition did not reserve producer custody")
	}
	release()
	var result answer
	select {
	case result = <-done:
	case <-time.After(time.Second):
		t.Fatal("root acquisition did not return after native completion")
	}
	if result.lease == nil || !errors.Is(result.err, errHostStageClosed) {
		t.Fatal("late native duplicate was published or lost")
	}
	result.lease.closeFile = func() error { return nil }
	if file, err := result.lease.File(); file != nil || err == nil {
		t.Fatal("late duplicate was borrowable")
	}
	if err := result.lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil || *cleaned != 1 {
		t.Fatal("released late duplicate did not permit explicit cleanup")
	}
}

func TestHostStageRootLeasePartialAdmissionAndBound(t *testing.T) {
	stage, cleaned := inertHostStageRoot(t)
	failure := errors.New("fixed duplicate validation refusal")
	stage.duplicateRoot = func() (*os.File, error) { return new(os.File), failure }
	lease, err := stage.AcquireRoot()
	if lease == nil || !errors.Is(err, failure) || len(stage.rootLeases) != 1 {
		t.Fatal("failed validation lost allocated duplicate custody")
	}
	lease.closeFile = func() error { return nil }
	if file, err := lease.File(); file != nil || !errors.Is(err, failure) {
		t.Fatal("failed validation exposed a capability")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	stage.duplicateRoot = func() (*os.File, error) { return new(os.File), nil }
	leases := make([]*RootLease, maxHostStageRootLeases)
	for i := range leases {
		leases[i] = inertHostStageLease(t, stage)
	}
	if lease, err := stage.AcquireRoot(); lease != nil || !errors.Is(err, ErrHostStageInUse) {
		t.Fatal("unbounded consumer handle acquisition")
	}
	for _, lease := range leases {
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if *cleaned != 0 {
		t.Fatal("release implicitly removed producer data")
	}
	if err := stage.Close(); err != nil || *cleaned != 1 {
		t.Fatal("bounded consumers did not release stage")
	}
}

func TestHostStageRootLeaseReleasingDoesNotBlockCloseRequest(t *testing.T) {
	stage, cleaned := inertHostStageRoot(t)
	lease := inertHostStageLease(t, stage)
	entered, finish := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(finish) })
	defer release()
	lease.closeFile = func() error { close(entered); <-finish; return nil }
	done := make(chan error, 1)
	go func() { done <- lease.Close() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("lease release did not reach the inert closer")
	}
	requireHostStageInUse(t, stage)
	if *cleaned != 0 {
		t.Fatal("cleanup overtook native duplicate close")
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lease close did not return after native completion")
	}
	if err := stage.Close(); err != nil || *cleaned != 1 {
		t.Fatal("completed release did not permit explicit cleanup")
	}
}
