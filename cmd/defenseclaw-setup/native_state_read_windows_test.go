// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// holdNativeStateFile opens path the way a writer that briefly locks the file
// does and returns the function that closes the handle.
func holdNativeStateFile(t *testing.T, path string, access, share uint32) func() {
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

func writeNativeActiveConnectorState(t *testing.T, dataRoot string) string {
	t.Helper()
	statePath := filepath.Join(dataRoot, "active_connector.json")
	if err := os.WriteFile(statePath, []byte(`{"version":3,"names":["codex"],"name":"codex"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return statePath
}

// GAP-0300: a holder that denies sharing for 300 ms delays Setup; it does
// not fail the install.
func TestReadNativeActiveConnectorsWaitsForTransientExclusiveHolder(t *testing.T) {
	dataRoot := t.TempDir()
	statePath := writeNativeActiveConnectorState(t, dataRoot)
	release := holdNativeStateFile(t, statePath, windows.GENERIC_READ|windows.GENERIC_WRITE, 0)
	timer := time.AfterFunc(300*time.Millisecond, release)
	defer timer.Stop()

	started := time.Now()
	names, err := readNativeActiveConnectors(dataRoot)
	if err != nil {
		t.Fatalf("readNativeActiveConnectors() error = %v", err)
	}
	if !reflect.DeepEqual(names, []string{"codex"}) {
		t.Fatalf("names = %v, want [codex]", names)
	}
	if elapsed := time.Since(started); elapsed < 250*time.Millisecond {
		t.Fatalf("read returned after %s, before the holder released the file", elapsed)
	}
}

// The gateway's private atomic publication keeps its renamed handle (write
// and delete access, read sharing only) while it validates the new file.
// os.Open fails against that handle; Setup's reader must not.
func TestReadNativeActiveConnectorsSharesWithPublisherHandle(t *testing.T) {
	dataRoot := t.TempDir()
	statePath := writeNativeActiveConnectorState(t, dataRoot)
	holdNativeStateFile(t, statePath,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, windows.FILE_SHARE_READ)

	if file, err := os.Open(statePath); err == nil {
		_ = file.Close()
		t.Log("os.Open shared with the publisher handle; the reader is still checked below")
	} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("os.Open error = %v, want a sharing violation", err)
	}
	started := time.Now()
	names, err := readNativeActiveConnectors(dataRoot)
	if err != nil {
		t.Fatalf("readNativeActiveConnectors() error = %v", err)
	}
	if !reflect.DeepEqual(names, []string{"codex"}) {
		t.Fatalf("names = %v, want [codex]", names)
	}
	if elapsed := time.Since(started); elapsed > nativeStateReadRetryDelay {
		t.Fatalf("read waited %s; a publisher handle must not need a retry", elapsed)
	}
}

// A holder that outlasts the retry window fails Setup closed with a message
// that says what holds the file and what to do.
func TestReadNativeActiveConnectorsFailsClosedAfterRetryWindow(t *testing.T) {
	dataRoot := t.TempDir()
	statePath := writeNativeActiveConnectorState(t, dataRoot)
	holdNativeStateFile(t, statePath, windows.GENERIC_READ|windows.GENERIC_WRITE, 0)
	var sleeps int
	previousSleep := nativeStateReadSleep
	nativeStateReadSleep = func(d time.Duration) { sleeps++; previousSleep(d) }
	t.Cleanup(func() { nativeStateReadSleep = previousSleep })

	names, err := readNativeActiveConnectors(dataRoot)
	if err == nil {
		t.Fatalf("readNativeActiveConnectors() = %v, want an error while the file is held", names)
	}
	if sleeps != nativeStateReadAttempts-1 {
		t.Fatalf("retries = %d, want %d", sleeps, nativeStateReadAttempts-1)
	}
	var busy *nativeStateFileBusyError
	if !errors.As(err, &busy) {
		t.Fatalf("error = %T %v, want *nativeStateFileBusyError", err, err)
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("error = %v, want it to wrap the sharing violation", err)
	}
	message := err.Error()
	for _, want := range []string{statePath, "is in use by", "run Setup again"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error %q does not contain %q", message, want)
		}
	}
	t.Logf("holders named by Restart Manager: %v", busy.Holders)
	if len(busy.Holders) > 0 && !strings.Contains(message, busy.Holders[0]) {
		t.Fatalf("error %q does not name holder %q", message, busy.Holders[0])
	}
}

// An unrelated error is not retried: only a lock is transient.
func TestReadBoundedNativeStateFileDoesNotRetryOversizedState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "active_connector.json")
	if err := os.WriteFile(statePath, []byte(strings.Repeat("x", 65)), 0o600); err != nil {
		t.Fatal(err)
	}
	previousSleep := nativeStateReadSleep
	nativeStateReadSleep = func(time.Duration) { t.Fatal("an oversized state file was retried") }
	t.Cleanup(func() { nativeStateReadSleep = previousSleep })
	if _, _, err := readBoundedNativeStateFile(statePath, 64); err == nil || !strings.Contains(err.Error(), "exceeds 64 bytes") {
		t.Fatalf("readBoundedNativeStateFile() error = %v, want the size limit", err)
	}
}
