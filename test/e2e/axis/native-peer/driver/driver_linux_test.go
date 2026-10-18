// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClosedBootstrapRefusesBeforeNativeOperations(t *testing.T) {
	record, retained, err := bootstrap([]string{"--receipt", "missing", "--evidence", "missing"}, wrapperAdmission{})
	if !errors.Is(err, errUnreviewed) || record["execution_performed"] != false || len(retained.pending) != 0 {
		t.Fatal("closed bootstrap reached a native operation")
	}
}

type failedReady struct{}

func (failedReady) Write([]byte) (int, error) { return 0, errors.New("fixed readiness failure") }

type noGrantRead struct{ t *testing.T }

func (r noGrantRead) Read([]byte) (int, error) {
	r.t.Fatal("failed READY consumed GRANT")
	return 0, io.EOF
}

func TestBootstrapHandshakeNeedsOneExactGrant(t *testing.T) {
	for _, grant := range []string{workerGrant, "", "wrong", workerGrant + workerGrant, workerGrant + "x"} {
		var ready bytes.Buffer
		if err := readyThenGrant(&ready, strings.NewReader(grant)); (err == nil) != (grant == workerGrant) || ready.String() != workerReady {
			t.Fatal("bootstrap grant acceptance differs")
		}
	}
	if err := readyThenGrant(failedReady{}, noGrantRead{t}); err == nil {
		t.Fatal("readiness failure accepted")
	}
}

func TestFinishedCustodyWaitWinsCanceledContext(t *testing.T) {
	done := make(chan struct{})
	close(done)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	complete := &outerCustodian{pidfd: -1, done: done, complete: true}
	if err := complete.stopAndWait(ctx); err != nil {
		t.Fatal(err)
	}
	pending := &outerCustodian{pidfd: -1, done: make(chan struct{}), starting: true}
	if !errors.Is(pending.stopAndWait(ctx), context.Canceled) || !pending.closed || !pending.starting {
		t.Fatal("pending start lost retained ownership")
	}
}

func TestBoundedCaptureRetainsPrefixOnOverflow(t *testing.T) {
	capture := &boundedCapture{}
	if _, err := capture.Write(bytes.Repeat([]byte{'x'}, outputLimit)); err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Write([]byte("oversize")); err == nil {
		t.Fatal("capture overflow accepted")
	}
	data, overflow := capture.snapshot()
	if len(data) != outputLimit || !overflow {
		t.Fatal("bounded failure prefix missing")
	}
}

func validWrapperResult() map[string]any {
	child := map[string]any{"scope": "fixed_linux_native_peer_offline_contributor_v1", "passed": true, "execution_performed": true, "production_certification": false, "common_launch_gate_qualified": false,
		"artifact_receipt_sha256": receiptSHA, "outer_namespace_cleanup_observed": true, "pending_outer_cleanup": float64(0), "pending_native_cleanup": float64(0),
		"outer_worker_ready_observed": true, "outer_worker_grant_sent": true, "owned_worker_result_observed": true,
		"host_outside_read_and_write_positive_controls": true, "original_canary_identities_and_bytes_preserved": true}
	cases := []any{}
	for _, mode := range []string{"argv", "stdio", "exit23", "boundaries"} {
		cases = append(cases, map[string]any{"mode": mode, "passed": true, "prepared": true, "started": true, "fixed_payload_marker_observed": true, "destroyed": true, "native_cleanup_observed": true, "exit_code": float64(23)})
	}
	child["cases"] = cases
	return child
}

func TestWrapperResultRequiresEveryFixedControlAndCleanup(t *testing.T) {
	if err := validateWrapperResult(validWrapperResult()); err != nil {
		t.Fatal(err)
	}
	for key := range validWrapperResult() {
		child := validWrapperResult()
		delete(child, key)
		if validateWrapperResult(child) == nil {
			t.Fatalf("missing result field admitted: %s", key)
		}
	}
	for _, key := range []string{"passed", "prepared", "started", "fixed_payload_marker_observed", "destroyed", "native_cleanup_observed", "exit_code", "mode"} {
		child := validWrapperResult()
		child["cases"].([]any)[2].(map[string]any)[key] = nil
		if validateWrapperResult(child) == nil {
			t.Fatalf("missing case assertion admitted: %s", key)
		}
	}
	child := validWrapperResult()
	child["cases"].([]any)[0].(map[string]any)["error"] = "fixed_failure"
	if validateWrapperResult(child) == nil {
		t.Fatal("case failure admitted")
	}
}

// Header-only inert fixture. It is parsed as data and never executed or mapped.
func staticELFFixture() []byte {
	data := make([]byte, 128)
	copy(data, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 62)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[24:], 0x1000)
	binary.LittleEndian.PutUint64(data[32:], 64)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], 1)
	binary.LittleEndian.PutUint32(data[64:], 1)
	binary.LittleEndian.PutUint32(data[68:], 5)
	binary.LittleEndian.PutUint64(data[80:], 0x1000)
	binary.LittleEndian.PutUint64(data[96:], 128)
	binary.LittleEndian.PutUint64(data[104:], 128)
	return data
}

func TestStaticELFRejectsLoaderAndOutOfRangeEntryAsData(t *testing.T) {
	if err := validateStaticELF(staticELFFixture()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(data []byte) { binary.LittleEndian.PutUint32(data[64:], 3) },
		func(data []byte) { binary.LittleEndian.PutUint32(data[64:], 2) },
		func(data []byte) { binary.LittleEndian.PutUint64(data[24:], 0x2000) },
		func(data []byte) { binary.LittleEndian.PutUint64(data[96:], 129) },
		func(data []byte) { binary.LittleEndian.PutUint16(data[16:], 3) },
	} {
		data := staticELFFixture()
		mutate(data)
		if validateStaticELF(data) == nil {
			t.Fatal("invalid image header admitted")
		}
	}
}

func TestHostFixtureParentNeverTreatsUnmappedUIDAsRootProof(t *testing.T) {
	for _, uid := range []uint32{0, 1001, 65534} {
		st := unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0777, Uid: uid}
		if trustedTemporaryParent(st) != (uid == 0) {
			t.Fatal("unmapped or user ownership became host-root proof")
		}
	}
	if trustedTemporaryParent(unix.Stat_t{Mode: unix.S_IFDIR | 0777, Uid: 0}) {
		t.Fatal("nonsticky host parent admitted")
	}
}
func TestHostFixtureCreationRetainsExactHeldParentAndFreshRoot(t *testing.T) {
	parentPath := t.TempDir()
	parent, err := openDirectory(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	f, err := createHostFixtureUnder(parent, parentPath, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	if err := privateDirectory(f.root); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Open(filepath.Join(parentPath, "dc-axis-native-peer-"+strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	a, err := opened.Stat()
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.root.Stat()
	if err != nil || !os.SameFile(a, b) {
		t.Fatal("held root differs from fresh created object")
	}
	if again, err := createHostFixtureUnder(parent, parentPath, strings.Repeat("a", 32)); err == nil || again != nil {
		t.Fatal("existing fixture reused")
	}
}
