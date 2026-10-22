// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ForeignHookFencePaths names stable per-account lock files in the protected
// guardian authorization directory. A digest keeps untrusted identity text
// out of a path. Neither file may be replaced while the deployment runs.
func ForeignHookFencePaths(dir, identity string) (admission, active string) {
	digest := sha256.Sum256([]byte(identity))
	base := filepath.Join(dir, fmt.Sprintf("foreign-hook-fence-%x", digest[:20]))
	return base + ".admission", base + ".active"
}

// LockForeignHookFence takes the per-account writer-preferred gate. A reader
// takes admission exclusively just long enough to enter active shared; a
// writer keeps admission exclusively through its active exclusive section.
// Once a removal writer is admitted, later exchanges cannot read the old
// ledger or finish a decision until its removal commit is settled.
func LockForeignHookFence(ctx context.Context, dir, identity string, writer bool) (func(), error) {
	admissionPath, activePath := ForeignHookFencePaths(dir, identity)
	admission, err := os.OpenFile(admissionPath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open foreign-hook admission fence: %w", err)
	}
	limit := 2 * time.Second
	if writer {
		limit = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	if err := lockForeignHookFile(ctx, admission, true); err != nil {
		cancel()
		_ = admission.Close()
		return nil, fmt.Errorf("enter foreign-hook admission fence: %w", err)
	}
	active, err := os.OpenFile(activePath, os.O_RDONLY, 0)
	if err == nil {
		err = lockForeignHookFile(ctx, active, writer)
	}
	if err != nil {
		if active != nil {
			_ = active.Close()
		}
		unlockForeignHookFile(admission)
		_ = admission.Close()
		cancel()
		return nil, fmt.Errorf("enter foreign-hook active fence: %w", err)
	}
	if !writer {
		unlockForeignHookFile(admission)
		_ = admission.Close()
	}
	cancel()
	return func() {
		unlockForeignHookFile(active)
		_ = active.Close()
		if writer {
			unlockForeignHookFile(admission)
			_ = admission.Close()
		}
	}, nil
}
