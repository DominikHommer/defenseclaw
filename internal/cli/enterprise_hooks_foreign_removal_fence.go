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
// for its turn (enterpriseForeignHookInProcessFence). Every holder is
// bounded: each holds the fence for one removal and its ledger commit.
const enterpriseForeignHookCleanupQueueWait = 2 * time.Minute

// acquireEnterpriseForeignHookCleanupFence takes the machine's foreign-hook
// cleanup fence: this guardian's turn within ctx, then the fence file within
// enterpriseForeignHookCleanupFenceWait. The gateway holds the same file
// until an allow has been sent; the guardian holds it from each removal
// through that removal's ledger commit. On error nothing is held and
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

// enterpriseForeignHookCleanupFence is one cleanup's hold on the machine's
// foreign-hook cleanup fence. lock takes it for one removal; commit records
// that removal's files in the removal ledger and releases it.
type enterpriseForeignHookCleanupFence interface {
	lock(connector string) error
	commit(connector string, removed []string) error
}

// enterpriseForeignHookRemovalGuard is the GuardRemoval of one connector's
// cleanup. Each removal takes the fence, runs, commits its files (none when
// it failed) and releases the fence before the cleanup reads anything else,
// so the fence never covers a scan. Once the fence is refused or a commit
// fails, the cleanup's later removals are refused without waiting again:
// those hooks stay in place, reported, and the guard keeps denying.
func enterpriseForeignHookRemovalGuard(connector string, fence enterpriseForeignHookCleanupFence) func([]string, func() error) error {
	var refused error
	return func(paths []string, remove func() error) error {
		if refused != nil {
			return refused
		}
		if err := fence.lock(connector); err != nil {
			refused = err
			return err
		}
		removeErr := remove()
		var removed []string
		if removeErr == nil {
			removed = paths
		}
		if err := fence.commit(connector, removed); err != nil {
			refused = err
			return errors.Join(removeErr, err)
		}
		return removeErr
	}
}

// enterpriseForeignHookInProcessFence is the fence of a cleanup the guardian
// runs in process with the user's identity (enterpriseForeignHookRunAsTarget,
// the Windows reconcile and its machine-policy pass). Its lock and commit
// act as the guardian (enterpriseForeignHookAsGuardian); commit records the
// account's removals.
type enterpriseForeignHookInProcessFence struct {
	account, home string
	unlock        func()
	committed     map[string]bool
}

func newEnterpriseForeignHookInProcessFence(account, home string) *enterpriseForeignHookInProcessFence {
	return &enterpriseForeignHookInProcessFence{account: account, home: home, committed: map[string]bool{}}
}

func (f *enterpriseForeignHookInProcessFence) lock(string) error {
	if f.unlock != nil {
		return errors.New("foreign-hook cleanup fence: this cleanup already holds it")
	}
	return enterpriseForeignHookAsGuardian(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), enterpriseForeignHookCleanupQueueWait)
		defer cancel()
		unlock, err := acquireEnterpriseForeignHookCleanupFence(ctx)
		if err == nil {
			f.unlock = unlock
		}
		return err
	})
}

// commit records removed and then releases the fence, even when the record
// could not run (the caller records what no commit did once it is the
// guardian again: uncommitted).
func (f *enterpriseForeignHookInProcessFence) commit(connector string, removed []string) error {
	if f.unlock == nil {
		return errors.New("foreign-hook cleanup fence: this cleanup does not hold it")
	}
	defer f.release()
	return enterpriseForeignHookAsGuardian(func() error {
		recordEnterpriseForeignHookRemovals(os.Stderr, f.account, f.home, connector, removed)
		for _, path := range removed {
			f.committed[path] = true
		}
		return nil
	})
}

// release lets go of the fence if this cleanup still holds it. Releasing
// needs no identity: it only unlocks and closes the open fence file.
func (f *enterpriseForeignHookInProcessFence) release() {
	if f.unlock != nil {
		f.unlock()
		f.unlock = nil
	}
}

// uncommitted lists the files of removed that no commit recorded.
func (f *enterpriseForeignHookInProcessFence) uncommitted(removed []string) []string {
	var out []string
	for _, path := range removed {
		if !f.committed[path] {
			out = append(out, path)
		}
	}
	return out
}
