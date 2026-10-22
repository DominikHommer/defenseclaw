// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// legacyWithFileLock is the Unix withFileLockMode of 0.8.10 through 1.0.3,
// step for step: unlink a sentinel older than 60 seconds, open or create it,
// flock it, run fn, unlock, then unlink. now is its clock, so a test can run
// it later than the real time; betweenUnlockAndUnlink runs where a preempted
// older writer sits between its unlock and its unlink.
func legacyWithFileLock(path string, now time.Time, betweenUnlockAndUnlink func(), fn func() error) error {
	lockPath := path + ".lock"
	const staleLockAge = 60 * time.Second
	if info, err := os.Stat(lockPath); err == nil {
		if now.Sub(info.ModTime()) > staleLockAge {
			_ = os.Remove(lockPath)
		}
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		if betweenUnlockAndUnlink != nil {
			betweenUnlockAndUnlink()
		}
		_ = os.Remove(lockPath)
	}()
	return fn()
}

func waitErr(t *testing.T, what string, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not finish", what)
	}
}

// An older writer that runs while this release holds the sentinel waits for
// it, however old the sentinel is, however long the hold lasts and however
// late the older writer runs; it then unlocks and unlinks the sentinel in its
// own order, and the next hold excludes it again.
func TestFileLockSentinelHeldByNewWriterNeverLooksStaleToOlderWriter(t *testing.T) {
	for _, tc := range []struct {
		name string
		// prepare runs before the first hold; it returns the older writer's
		// clock offset from the real time.
		prepare func(t *testing.T, path string) time.Duration
	}{
		{"aged sentinel from an earlier release", func(t *testing.T, path string) time.Duration {
			if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
				t.Fatal(err)
			}
			aged := time.Now().Add(-2 * time.Hour)
			if err := os.Chtimes(path+".lock", aged, aged); err != nil {
				t.Fatal(err)
			}
			return 0
		}},
		{"sentinel this release kept from a hold days ago", func(t *testing.T, path string) time.Duration {
			if err := withFileLock(path, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			return 48 * time.Hour
		}},
		{"hold outlasting the older writer's stale age", func(*testing.T, string) time.Duration {
			return 10 * time.Minute
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".hookcfg")
			offset := tc.prepare(t, path)
			for round := 0; round < 2; round++ {
				inHold := make(chan struct{})
				releaseHold := make(chan struct{})
				newDone := make(chan error, 1)
				go func() {
					newDone <- withFileLock(path, func() error {
						close(inHold)
						<-releaseHold
						return nil
					})
				}()
				<-inHold
				legacyEntered := make(chan struct{})
				legacyDone := make(chan error, 1)
				go func() {
					legacyDone <- legacyWithFileLock(path, time.Now().Add(offset), nil, func() error {
						close(legacyEntered)
						return nil
					})
				}()
				select {
				case <-legacyEntered:
					close(releaseHold)
					t.Fatalf("round %d: the older writer took the sentinel for stale and ran during the hold", round)
				case <-time.After(300 * time.Millisecond):
				}
				close(releaseHold)
				waitErr(t, "new writer", newDone)
				select {
				case <-legacyEntered:
				case <-time.After(10 * time.Second):
					t.Fatalf("round %d: the older writer never got the lock after the hold", round)
				}
				waitErr(t, "older writer", legacyDone)
				if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
					t.Fatalf("round %d: the older writer should unlink the sentinel after it unlocks, got %v", round, err)
				}
			}
		})
	}
}

// An older writer that unlocks and is preempted before it unlinks lets a
// waiting new writer verify the inode it is about to unlink. Once it unlinks,
// a third writer makes a new inode and runs beside the hold. The hold cannot
// stop that, so it must not report success.
func TestFileLockReportsOlderWriterUnlinkAfterUnlockDuringTheHold(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".hookcfg")
	inLegacy := make(chan struct{})
	releaseLegacy := make(chan struct{})
	newEntered := make(chan struct{})
	legacyDone := make(chan error, 1)
	go func() {
		legacyDone <- legacyWithFileLock(path, time.Now(), func() {
			// Unlocked, not yet unlinked: the waiting new writer runs now.
			<-newEntered
		}, func() error {
			close(inLegacy)
			<-releaseLegacy
			return nil
		})
	}()
	<-inLegacy

	thirdRan := make(chan bool, 1)
	newDone := make(chan error, 1)
	go func() {
		newDone <- withFileLock(path, func() error {
			close(newEntered)
			if err := <-legacyDone; err != nil {
				return err
			}
			entered := false
			err := legacyWithFileLock(path, time.Now(), nil, func() error {
				entered = true
				return nil
			})
			thirdRan <- entered
			return err
		})
	}()
	// Let the new writer open the older writer's inode and wait on it.
	time.Sleep(150 * time.Millisecond)
	close(releaseLegacy)

	var err error
	select {
	case err = <-newDone:
	case <-time.After(10 * time.Second):
		t.Fatal("new writer did not finish")
	}
	if !<-thirdRan {
		t.Fatal("precondition: the third writer should have run beside the hold on a new inode")
	}
	if err == nil || !strings.Contains(err.Error(), "unlinked or replaced while this writer held it") {
		t.Fatalf("hold reported %v after another writer ran beside it, want the unlinked-sentinel error", err)
	}
}

// Whatever unlinks or replaces the sentinel during a hold, the hold reports
// that it could not prove its exclusion, and keeps the callback's own error.
func TestFileLockReportsASentinelThatChangedDuringTheHold(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(lockPath string) error
	}{
		{"unlinked", os.Remove},
		{"replaced", func(lockPath string) error {
			if err := os.Remove(lockPath); err != nil {
				return err
			}
			return os.WriteFile(lockPath, nil, 0o600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".hookcfg")
			err := withFileLock(path, func() error { return tc.change(path + ".lock") })
			if err == nil || !strings.Contains(err.Error(), "unlinked or replaced while this writer held it") {
				t.Fatalf("got %v, want the unlinked-sentinel error", err)
			}
			callbackErr := os.ErrPermission
			err = withFileLock(path, func() error {
				if err := tc.change(path + ".lock"); err != nil {
					return err
				}
				return callbackErr
			})
			if err == nil || !strings.Contains(err.Error(), "unlinked or replaced") || !strings.Contains(err.Error(), callbackErr.Error()) {
				t.Fatalf("got %v, want both the callback error and the unlinked-sentinel error", err)
			}
		})
	}
	// An untouched hold returns the callback's error itself.
	path := filepath.Join(t.TempDir(), ".hookcfg")
	if err := withFileLock(path, func() error { return os.ErrExist }); err != os.ErrExist {
		t.Fatalf("got %v, want the callback's own error value", err)
	}
	info, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().After(time.Now().Add(300 * 24 * time.Hour)) {
		t.Fatalf("sentinel modification time %s is not stamped ahead", info.ModTime())
	}
}
