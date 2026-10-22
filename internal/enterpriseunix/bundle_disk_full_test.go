// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// GAP-0609: a bundle apply on a full state volume reported
// bundle_state_unreadable ("cannot write the policy bundle receipt ...: no
// space left on device"), a read problem, for a write that failed. Every
// bundle-state write that fails for lack of space is disk_full, with the
// write cause and the next step; the last good policy keeps enforcing.
func TestBundleStateWriteOnAFullVolumeIsDiskFull(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	enospc := &fs.PathError{Op: "mkdir", Path: "/var/lib/defenseclaw-enterprise/receipts", Err: syscall.ENOSPC}
	b.env.bundleFault = func(phase string) error {
		if phase == "private-dir receipts" {
			return enospc
		}
		return nil
	}
	r := b.apply(b.dir(1, v1))
	b.env.bundleFault = nil
	if r.OK || len(r.Errors) == 0 || r.Errors[0].Code != codeDiskFull || hasMessageCode(r.Errors, codeBundleStateUnreadable) {
		t.Fatalf("receipt write on a full volume: ok %v, errors %+v; want disk_full first, no %s", r.OK, r.Errors, codeBundleStateUnreadable)
	}
	for _, want := range []string{"cannot write the policy bundle receipt", "no space left on device", "free space on that filesystem"} {
		if !strings.Contains(r.Errors[0].Message, want) {
			t.Fatalf("disk_full message %q lacks %q", r.Errors[0].Message, want)
		}
	}

	// A step after the receipt that fails for lack of space fails the
	// receipt as disk_full, not apply_failed.
	b.mapPromotedBundleOwners(1)
	requireOK(t, b.apply(b.dir(1, v1)))
	b.env.bundleFault = func(phase string) error {
		if phase == enterprisebundle.StateStaged {
			return fmt.Errorf("promote: %w", enospc)
		}
		return nil
	}
	r = b.apply(b.dir(2, v2))
	b.env.bundleFault = nil
	if r.OK || !hasMessageCode(r.Errors, string(enterprisebundle.CodeDiskFull)) || hasMessageCode(r.Errors, string(enterprisebundle.CodeApplyFailed)) {
		t.Fatalf("staged step on a full volume: ok %v, errors %+v; want disk_full", r.OK, r.Errors)
	}
	if rc := b.receipt(bundleID(2)); rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeDiskFull {
		t.Fatalf("failed receipt = %s %s, want failed disk_full", rc.State, rc.ErrorCode)
	}

	// A state record the run could not write is a disk_full warning too;
	// any other write failure keeps its code.
	if got := stateWriteCode(fmt.Errorf("stage policy-state.json: %w", enospc), codeState); got != codeDiskFull {
		t.Fatalf("stateWriteCode(ENOSPC) = %s", got)
	}
	if got := stateWriteCode(errors.New("permission denied"), codeState); got != codeState {
		t.Fatalf("stateWriteCode(EACCES) = %s", got)
	}
}
