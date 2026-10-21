// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func holdConnectorStateFile(t *testing.T, path string, access, share uint32) func() {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("hold %s: %v", path, err)
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = windows.CloseHandle(handle) }) }
	t.Cleanup(release)
	return release
}

// GAP-0300: the private publication's renamed handle (write and delete
// access, read sharing only) must not make a reader fail.
func TestReadActiveConnectorStateSharesWithPublisherHandle(t *testing.T) {
	dir := t.TempDir()
	if err := SaveActiveConnectors(dir, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	holdConnectorStateFile(t, filepath.Join(dir, activeConnectorFile),
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, windows.FILE_SHARE_READ)

	names, exists, err := ReadActiveConnectorState(dir)
	if err != nil || !exists || !reflect.DeepEqual(names, []string{"codex"}) {
		t.Fatalf("ReadActiveConnectorState() = %v, %v, %v; want [codex], true, nil", names, exists, err)
	}
}

// A holder that denies sharing for 300 ms delays the read; it does not fail.
func TestReadActiveConnectorStateWaitsForTransientExclusiveHolder(t *testing.T) {
	dir := t.TempDir()
	if err := SaveActiveConnectors(dir, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	release := holdConnectorStateFile(t, filepath.Join(dir, activeConnectorFile),
		windows.GENERIC_READ|windows.GENERIC_WRITE, 0)
	timer := time.AfterFunc(300*time.Millisecond, release)
	defer timer.Stop()

	names, exists, err := ReadActiveConnectorState(dir)
	if err != nil || !exists || !reflect.DeepEqual(names, []string{"codex"}) {
		t.Fatalf("ReadActiveConnectorState() = %v, %v, %v; want [codex], true, nil", names, exists, err)
	}
}

// A holder that outlasts the retry window is reported, never read as absent.
func TestReadActiveConnectorStateReportsPersistentLock(t *testing.T) {
	dir := t.TempDir()
	if err := SaveActiveConnectors(dir, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	holdConnectorStateFile(t, filepath.Join(dir, activeConnectorFile),
		windows.GENERIC_READ|windows.GENERIC_WRITE, 0)
	previousSleep := connectorStateReadSleep
	var sleeps int
	connectorStateReadSleep = func(time.Duration) { sleeps++ }
	t.Cleanup(func() { connectorStateReadSleep = previousSleep })

	_, exists, err := ReadActiveConnectorState(dir)
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || exists {
		t.Fatalf("ReadActiveConnectorState() exists=%v err=%v, want a sharing violation", exists, err)
	}
	if sleeps != connectorStateReadAttempts-1 {
		t.Fatalf("retries = %d, want %d", sleeps, connectorStateReadAttempts-1)
	}
}

// Readers racing a real writer never see a lock or a partial file.
func TestReadActiveConnectorStateDuringConcurrentPublication(t *testing.T) {
	dir := t.TempDir()
	if err := SaveActiveConnectors(dir, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		sets := [][]string{{"codex"}, {"claudecode", "codex"}}
		for i := 0; i < 100; i++ {
			if err := SaveActiveConnectors(dir, sets[i%2]); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("SaveActiveConnectors() error = %v", err)
			}
			return
		default:
		}
		names, exists, err := ReadActiveConnectorState(dir)
		if err != nil || !exists || len(names) == 0 {
			t.Fatalf("ReadActiveConnectorState() during publication = %v, %v, %v", names, exists, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, activeConnectorFile)); err != nil {
			t.Fatalf("state file vanished during publication: %v", err)
		}
	}
}
