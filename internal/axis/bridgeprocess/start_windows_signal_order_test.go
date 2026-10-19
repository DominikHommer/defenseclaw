// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"errors"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
)

// This tests the native signal ordering with injected results only. It does
// not allocate a Job, create a process, or claim that a signal is completion.
func TestWindowsJobSignalPrecedesRootFallbackAndRequiresLaterObservation(t *testing.T) {
	custody := &windowsCustody{}
	jobCalls, rootCalls := 0, 0
	signals, err := custody.signalJobFirst(func() error {
		jobCalls++
		return nil
	}, func() (bool, error) {
		rootCalls++
		return true, syscall.Errno(5)
	})
	if err != nil || !custody.jobTerminationIssued || jobCalls != 1 || rootCalls != 0 ||
		!signals.JobAttempted || signals.JobFailed || signals.RootAttempted || signals.RootFailed {
		t.Fatal("successful Job signal incorrectly attempted or required redundant root termination")
	}
	if custody.complete {
		t.Fatal("signal was mistaken for retained root and Job terminal observation")
	}
	// The next bounded poll, or a retry after its deadline, must observe
	// root-signaled and JobActive0 without issuing a second native signal.
	signals, err = custody.signalJobFirst(func() error {
		jobCalls++
		return syscall.Errno(5)
	}, func() (bool, error) {
		rootCalls++
		return true, syscall.Errno(5)
	})
	if err != nil || jobCalls != 1 || rootCalls != 0 || signals != (WindowsNativeSignalResult{}) {
		t.Fatal("already-issued Job termination was repeated before terminal observation")
	}
}

func TestWindowsFailedJobSignalRetainsOwnerEvenWhenRootFallbackSucceeds(t *testing.T) {
	custody := &windowsCustody{}
	jobFailure := syscall.Errno(6)
	rootFailure := syscall.Errno(5)
	for _, test := range []struct {
		name          string
		fallback      func() (bool, error)
		rootAttempted bool
		rootFailed    bool
		rootCode      uint32
	}{
		{"root_failed", func() (bool, error) { return true, rootFailure }, true, true, 5},
		{"root_succeeded", func() (bool, error) { return true, nil }, true, false, 0},
		{"root_already_done", func() (bool, error) { return false, nil }, false, false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			signals, err := custody.signalJobFirst(func() error { return jobFailure }, test.fallback)
			if !errors.Is(err, bridgeowner.ErrCleanup) || !errors.Is(err, jobFailure) ||
				custody.jobTerminationIssued || custody.complete || !signals.JobAttempted ||
				!signals.JobFailed || signals.JobWin32 != 6 || signals.RootAttempted != test.rootAttempted ||
				signals.RootFailed != test.rootFailed || signals.RootWin32 != test.rootCode {
				t.Fatal("failed Job signal lost partial cleanup or closed role/status evidence")
			}
			if test.rootFailed && !errors.Is(err, rootFailure) {
				t.Fatal("failed root fallback lost its private native error")
			}
		})
	}
	// The exact owner remains retryable; a later successful Job signal still
	// does not certify cleanup without root and Job terminal observations.
	signals, err := custody.signalJobFirst(func() error { return nil }, func() (bool, error) {
		t.Fatal("successful retry invoked redundant root fallback")
		return true, nil
	})
	if err != nil || !custody.jobTerminationIssued || signals.RootAttempted || custody.complete {
		t.Fatal("successful Job retry changed completion or fallback semantics")
	}
}
