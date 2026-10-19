// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"golang.org/x/sys/windows"
)

// A failed cleanup retains this no-child owner until the test process exits.
// In particular, a failed CloseHandle must not be hidden by test teardown.
var windowsNoChildRetained struct {
	sync.Mutex
	owners []*windowsNoChildHeld
}

type windowsNoChildHeld struct {
	custody *windowsCustody
	owner   *bridgeowner.Owner
}

func retainWindowsNoChild(held *windowsNoChildHeld) {
	windowsNoChildRetained.Lock()
	windowsNoChildRetained.owners = append(windowsNoChildRetained.owners, held)
	windowsNoChildRetained.Unlock()
}

func releaseWindowsNoChild(held *windowsNoChildHeld) {
	windowsNoChildRetained.Lock()
	defer windowsNoChildRetained.Unlock()
	for index, owner := range windowsNoChildRetained.owners {
		if owner == held {
			windowsNoChildRetained.owners[index] = nil
			return
		}
	}
}

// This is a real Windows handle test with no CreateProcess, PSEC, image, or
// workload. It reproduces the three overlapped pipe Take/duplicate transfers
// and an empty Job, then observes the same cleanup owner both before and after
// bridgeowner.New accepts the parent endpoints.
func TestWindowsNoChildOverlappedPipeAndJobCustody(t *testing.T) {
	for _, handoff := range []bool{false, true} {
		name := "pre_owner"
		if handoff {
			name = "owner_handoff"
		}
		t.Run(name, func(t *testing.T) {
			custody := &windowsCustody{serial: make(chan struct{}, 1), launchDone: make(chan struct{})}
			held := &windowsNoChildHeld{custody: custody}
			retainWindowsNoChild(held)
			cleanup := func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var ownerErr error
				if held.owner != nil {
					ownerErr = held.owner.Close(ctx)
				}
				custodyErr := custody.StopAndWait(ctx)
				return errors.Join(ownerErr, custodyErr)
			}
			defer func() {
				if err := cleanup(); err != nil {
					t.Errorf("no-child retained custody remained incomplete: %v", err)
					return
				}
				releaseWindowsNoChild(held)
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var channels []bridgeowner.PrivatePipe
			for _, direction := range []bridgeowner.Direction{bridgeowner.ToPeer, bridgeowner.FromPeer, bridgeowner.FromPeer} {
				setup, err := bridgeowner.NewOverlappedPrivatePipe(ctx, direction)
				if setup != nil {
					custody.pipeSetup = append(custody.pipeSetup, setup)
				}
				if err != nil {
					t.Fatalf("no-child pipe setup refused: %v", err)
				}
				channel, err := setup.Take()
				if channel.Parent != nil {
					custody.preOwnerPipes = append(custody.preOwnerPipes, channel.Parent)
				}
				if channel.Child != nil {
					custody.startupCopies = append(custody.startupCopies, channel.Child)
				}
				if err != nil {
					t.Fatalf("no-child pipe transfer refused: %v", err)
				}
				copy, err := windowsInheritableCopy(channel.Child)
				if copy != nil {
					custody.startupCopies = append(custody.startupCopies, copy)
				}
				if err != nil {
					t.Fatalf("no-child inheritable copy refused: %v", err)
				}
				channels = append(channels, channel)
			}
			job, err := windows.CreateJobObject(nil, nil)
			if job != 0 && job != windows.InvalidHandle {
				custody.job = job
			}
			if err != nil || custody.job == 0 {
				t.Fatalf("no-child Job creation refused: %v", err)
			}

			if handoff {
				_, binding, _ := windowsBootstrapFixture(0, 0)
				parents := custody.preOwnerPipes
				custody.preOwnerPipes = nil
				owner, err := bridgeowner.New(ctx, binding, bridgeowner.Pipes{
					Input: channels[0].Parent, Output: channels[1].Parent,
					Diagnostics: channels[2].Parent, Custody: custody,
				}, bridgeowner.Limits{WriteTimeout: time.Second, CleanupTimeout: 5 * time.Second})
				held.owner = owner
				if owner == nil {
					custody.preOwnerPipes = parents
				}
				if err != nil {
					t.Fatalf("no-child protocol handoff refused: %v", err)
				}
			}
			if err := cleanup(); err != nil {
				t.Fatalf("no-child exact cleanup failed: %v", err)
			}
			custody.mu.Lock()
			complete := custody.complete && !custody.uncertain && custody.job == 0 && custody.process == 0 && custody.thread == 0
			for _, file := range append(append([]*os.File{}, custody.preOwnerPipes...), custody.startupCopies...) {
				complete = complete && file == nil
			}
			for _, setup := range custody.pipeSetup {
				complete = complete && setup == nil
			}
			custody.mu.Unlock()
			if !complete {
				t.Fatal("no-child custody reported completion with retained native handles")
			}
		})
	}
}
