// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// ensureEnterpriseForeignHookRemovalFence prepares the stable lock inode
// before the guardian can publish a removal. The gateway gets read access
// through the same narrow ownership rule as the removal ledger. Reconcile
// never replaces this file, including on an upgrade.
func ensureEnterpriseForeignHookRemovalFence(dir string) error {
	for _, name := range []string{enterprisepolicy.ForeignHookRemovalsFenceFile, enterprisepolicy.ForeignHookCleanupFenceFile} {
		if err := ensureEnterpriseForeignHookFenceFile(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func ensureEnterpriseForeignHookFenceFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
		if createErr == nil {
			createErr = file.Close()
		}
		if createErr != nil && !errors.Is(createErr, os.ErrExist) {
			return fmt.Errorf("create foreign-hook removal fence: %w", createErr)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect foreign-hook removal fence: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		return fmt.Errorf("foreign-hook removal fence %s is not an empty regular file", path)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("protect foreign-hook removal fence: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return fmt.Errorf("own foreign-hook removal fence: %w", err)
	}
	return enterpriseHookAuthorizationFileTrustCheck(path)
}

// enterpriseForeignHookCleanupQueue admits this guardian's cleanups to the
// machine's foreign-hook cleanup fence one at a time, in arrival order. A
// cleanup waiting for another one of this process waits here, within its
// own bound, and never against enterpriseForeignHookCleanupFenceWait: that
// budget is only for the gateway's exchanges, each of which holds the fence
// file for one bounded allow (gateway foreignHookFenceWait).
var enterpriseForeignHookCleanupQueue = make(chan struct{}, 1)

// enterpriseForeignHookCleanupFenceWait bounds the wait for the fence file
// once this guardian's turn has come. Replaceable in tests.
var enterpriseForeignHookCleanupFenceWait = 5 * time.Second

// enterpriseForeignHookCleanupQueueWait bounds an in-process cleanup's wait
// for its turn (withEnterpriseForeignHookCleanupFence). Every holder is
// bounded: a per-user worker by its timeout, an in-process cleanup by one
// connector's cleanup of one account.
const enterpriseForeignHookCleanupQueueWait = 2 * time.Minute

// acquireEnterpriseForeignHookCleanupFence takes the machine's foreign-hook
// cleanup fence: this guardian's turn within ctx, then the fence file within
// enterpriseForeignHookCleanupFenceWait. The gateway holds the same file
// until an allow has been sent; the guardian holds it from a cleanup's first
// removal through the removal-ledger commit. On error nothing is held and
// the caller removes nothing: the existing foreign-hook guard stays. The
// fence belongs to the machine guardian, even when the cleanup target keeps
// its hook scripts in a different per-user data directory. The returned
// function releases the fence and may be called more than once.
func acquireEnterpriseForeignHookCleanupFence(ctx context.Context) (func(), error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return func() {}, nil
	}
	dataDir := cfg.DataDir
	if !filepath.IsAbs(dataDir) {
		return nil, errors.New("foreign-hook cleanup data directory is unverified")
	}
	dir, err := prepareEnterpriseHookAuthorizationDir(dataDir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, enterprisepolicy.ForeignHookCleanupFenceFile)
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return nil, err
	}
	select {
	case enterpriseForeignHookCleanupQueue <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("foreign-hook cleanup fence unavailable: another cleanup holds it: %w", ctx.Err())
	}
	lockCtx, cancel := context.WithTimeout(ctx, enterpriseForeignHookCleanupFenceWait)
	defer cancel()
	unlock, err := enterprisepolicy.LockForeignHookRemovals(lockCtx, path)
	if err != nil {
		<-enterpriseForeignHookCleanupQueue
		return nil, fmt.Errorf("foreign-hook cleanup fence unavailable: %w", err)
	}
	return sync.OnceFunc(func() {
		unlock()
		<-enterpriseForeignHookCleanupQueue
	}), nil
}

// withEnterpriseForeignHookCleanupFence runs one in-process cleanup (a
// single connector of a single account, with its ledger commit) under the
// cleanup fence. If the fence cannot be taken, fn does not run.
func withEnterpriseForeignHookCleanupFence(fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), enterpriseForeignHookCleanupQueueWait)
	defer cancel()
	unlock, err := acquireEnterpriseForeignHookCleanupFence(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}
