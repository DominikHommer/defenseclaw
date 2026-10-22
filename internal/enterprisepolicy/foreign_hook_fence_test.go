// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestForeignHookRemovalFenceIsPerAccountAndBlocksLaterExchanges(t *testing.T) {
	dir := t.TempDir()
	for _, identity := range []string{"1001", "1002"} {
		admission, active := ForeignHookFencePaths(dir, identity)
		for _, path := range []string{admission, active} {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	writerUnlock, err := LockForeignHookFence(t.Context(), dir, "1001", true)
	if err != nil {
		t.Fatal(err)
	}
	otherUnlock, err := LockForeignHookFence(t.Context(), dir, "1002", false)
	if err != nil {
		writerUnlock()
		t.Fatalf("another account waited on the removal: %v", err)
	}
	otherUnlock()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if unlock, err := LockForeignHookFence(ctx, dir, "1001", false); !errors.Is(err, context.DeadlineExceeded) {
		if unlock != nil {
			unlock()
		}
		writerUnlock()
		t.Fatalf("exchange crossed an admitted removal: %v", err)
	}
	writerUnlock()
	readerUnlock, err := LockForeignHookFence(t.Context(), dir, "1001", false)
	if err != nil {
		t.Fatalf("exchange did not resume after the removal: %v", err)
	}
	readerUnlock()
}
