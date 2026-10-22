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

package openshell

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// lifecycleLockFile, in the account's OpenShell configuration directory,
// keeps DefenseClaw from creating or starting a sandbox on the account's
// gateway while DefenseClaw restarts or upgrades that gateway: the
// restart's or the upgrade's check of the sandboxes holds only until one
// starts, and an upgrade's restart comes minutes after it. A restart or an
// upgrade holds it exclusively from its check to the healthy gateway after
// it (LockGatewayLifecycle); a create or a start holds it shared over
// OpenShell's call (LockSandboxStart), so a sandbox started before the
// check is in the list the check reads, and one started after waits. It
// is advisory, between DefenseClaw processes of the account (the CLI and
// its sandbox daemon): another OpenShell client is not held back.
const lifecycleLockFile = ".defenseclaw-lifecycle.lock"

// ErrGatewayBusy refuses a create or a start while DefenseClaw restarts or
// upgrades the OpenShell gateway, and a restart or an upgrade while
// another is under way or a create or a start does not end in time.
var ErrGatewayBusy = errors.New("openshell: DefenseClaw is restarting or upgrading the OpenShell gateway")

// lifecycleLockWait bounds how long a restart or an upgrade waits for the
// creates and starts in flight, each of which holds the lock only for
// OpenShell's call.
var lifecycleLockWait = 2 * time.Minute

// lifecycleLockPoll is how often that wait tries the lock again.
const lifecycleLockPoll = 100 * time.Millisecond

// lifecycleLockPath is the lock file of the OpenShell configuration
// directory dir ("" is UserConfigDir). It makes a missing directory
// (owner only), so an arriving sandbox operation and a first rollback
// always contend on the same inode.
func lifecycleLockPath(dir string) (string, error) {
	if dir == "" {
		var err error
		if dir, err = UserConfigDir(); err != nil {
			return "", err
		}
	}
	dir, err := resolveConfigDir(dir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("openshell: create %s for the gateway lifecycle lock: %w", dir, err)
	}
	return filepath.Join(dir, lifecycleLockFile), nil
}

// LockGatewayLifecycle takes the lifecycle lock of the OpenShell
// configuration directory dir ("" is UserConfigDir) for a restart or an
// upgrade of its gateway, waiting for the creates and starts in flight,
// up to lifecycleLockWait (ErrGatewayBusy after it) or the end of ctx.
// unlock releases it.
func LockGatewayLifecycle(ctx context.Context, dir string) (unlock func(), err error) {
	path, err := lifecycleLockPath(dir)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lifecycleLockWait)
	for {
		u, lerr := tryLockFile(path, true)
		if !errors.Is(lerr, errLockHeld) {
			return u, lerr
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: another restart or upgrade, or a sandbox create or start, held it for %s; try again once it is done", ErrGatewayBusy, lifecycleLockWait)
		}
		t := time.NewTimer(lifecycleLockPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// LockSandboxStart takes the lifecycle lock of the OpenShell configuration
// directory dir ("" is UserConfigDir) for a create or a start of a sandbox,
// shared with the others, and refuses with ErrGatewayBusy at once while a
// restart or an upgrade holds it. unlock releases it.
func LockSandboxStart(dir string) (unlock func(), err error) {
	path, err := lifecycleLockPath(dir)
	if err != nil {
		return nil, err
	}
	unlock, err = tryLockFile(path, false)
	if errors.Is(err, errLockHeld) {
		return nil, ErrGatewayBusy
	}
	return unlock, err
}

// LockSandboxCommand holds the lifecycle lock throughout a DefenseClaw
// sandbox command. A rollback holds it exclusively through its final
// stopped check and restart; a command already admitted cannot cross that
// decision, and a new command waits until the rollback completes.
func LockSandboxCommand(ctx context.Context, dir string) (func(), error) {
	path, err := lifecycleLockPath(dir)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lifecycleLockWait)
	for {
		unlock, lockErr := tryLockFile(path, false)
		if lockErr == nil {
			return unlock, nil
		}
		if !errors.Is(lockErr, errLockHeld) {
			return nil, lockErr
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: wait for the gateway rollback to finish, then retry the sandbox command", ErrGatewayBusy)
		}
		t := time.NewTimer(lifecycleLockPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// LifecycleDrained is the line `defenseclaw-gateway sandbox-daemon drain`
// prints once it holds the account's lifecycle lock (LockGatewayLifecycle)
// and found nothing a stop of the account's gateway would end with no
// flush (CheckAccountGateways): the managed lifecycle, which runs it as the
// account, stops the account's units only after it, and lets the drain go
// once they are stopped.
const LifecycleDrained = "defenseclaw: OpenShell gateway lifecycle held, nothing to flush"

// CheckAccountGateways is the check a drain makes before the managed
// lifecycle stops the account's gateway: every local gateway registered for
// the account (RegistrationNames) must report each sandbox on it stopped
// (CheckSandboxesStopped, which refuses one it cannot read unless no
// MicroVM runs as the account), and no MicroVM may run as the account
// (vms), whatever gateway or client started it.
func CheckAccountGateways(ctx context.Context, vms VMCount) error {
	for _, name := range RegistrationNames(DiscoverOptions{}) {
		reg, err := Discover(DiscoverOptions{Gateway: name})
		if err != nil {
			if rerr := unreachableRefusal(ctx, ErrUnflushed, fmt.Errorf("the registration %s is not usable: %w", name, err), vms, "try again"); rerr != nil {
				return rerr
			}
			continue
		}
		if !reg.Local() {
			continue
		}
		c, err := Dial(reg, ClientOptions{RPCTimeout: 10 * time.Second})
		if err != nil {
			if rerr := unreachableRefusal(ctx, ErrUnflushed, fmt.Errorf("no connection to %s: %w", name, err), vms, "try again"); rerr != nil {
				return rerr
			}
			continue
		}
		err = CheckSandboxesStopped(ctx, c, vms)
		_ = c.Close()
		if err != nil {
			return fmt.Errorf("gateway %s: %w", name, err)
		}
	}
	n, err := vms(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("%w (the MicroVMs of this account could not be counted: %v); try again", ErrUnflushed, err)
	case n > 0:
		return fmt.Errorf("%w (%s run as this account, which the gateway's stop would end with no flush); stop them, then try again",
			ErrUnflushed, plural(n, "MicroVM", "MicroVMs"))
	}
	return nil
}

// errLockHeld is a lock another holder keeps.
var errLockHeld = errors.New("openshell: lock held")
