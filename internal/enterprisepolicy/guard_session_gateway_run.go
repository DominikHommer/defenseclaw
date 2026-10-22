// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The gateway's run mark (1.0.4 guard review loop round 3: any doubt
// blocks).
//
// A block ends an account's earlier allows only through a change the hook
// can read: the key's removal, its revocation mark or the block record.
// When the operating system refuses all three, the gateway owes the
// revocation (internal/gateway foreign_hook_revocation_owed.go), but the
// hook cannot see that, and a refusal the hook cannot predict (an I/O
// error, a security module rule that denies only the gateway) leaves the
// mark folder looking writable. So the outage path does not trust a
// gateway that did not end cleanly:
//
//   - a standalone gateway adds an empty file, <root name>.gateway-running,
//     to the folder of the revocation marks (publishedSessionMarkDir) before
//     it answers anything, while that folder still takes a change;
//   - it removes the file only as its very last step, when it stops with
//     nothing owed (no revocation that did not take, saved or not);
//   - during an outage the hook allows nothing while the file is there
//     (publishedSessionGatewayRunEnded): the gateway still runs and does not
//     answer, it ended without removing it (a crash, a kill, a host that
//     lost power), or it stopped owing a revocation. A gateway that finds
//     the file when it starts (its previous run did not end cleanly) ends
//     every account's key before any allow it publishes carries one.
//
// The file is a new file in a folder only root, SYSTEM, Administrators and
// the gateway service can add to, so no standard user can make or remove
// it. Any error reading it blocks.

// publishedSessionGatewayRunName follows the record folder's name in the
// name of the gateway's run mark.
const publishedSessionGatewayRunName = "gateway-running"

// errPublishedSessionGatewayRunning is the hook's refusal while the run
// mark is there.
var errPublishedSessionGatewayRunning = errors.New("the DefenseClaw gateway that wrote the records has not ended cleanly: it still runs and did not answer, it ended without settling every revocation, or it stopped unexpectedly")

// publishedSessionGatewayRunPath is the gateway's run mark of the record
// folder root.
func publishedSessionGatewayRunPath(root string) (string, bool) {
	keyDir, rootPrefix, ok := publishedSessionKeyRoot(root)
	if !ok {
		return "", false
	}
	return filepath.Join(publishedSessionMarkDir(filepath.Clean(strings.TrimSpace(root)), keyDir), rootPrefix+publishedSessionGatewayRunName), true
}

// MarkPublishedSessionGatewayRunning adds the gateway's run mark for the
// record folder root, flushes its folder and reads it back. found reports a
// mark an earlier run left (it did not end cleanly), or one that cannot be
// read: what that run decided may not have reached the folders. An error
// means this run has no mark, and none of its allows may carry a key.
func MarkPublishedSessionGatewayRunning(root string) (found bool, err error) {
	path, ok := publishedSessionGatewayRunPath(root)
	if !ok {
		return false, fmt.Errorf("no protected session record folder %q", root)
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode().IsRegular():
		return true, nil
	case err == nil:
		return true, fmt.Errorf("the gateway run mark %s is not a regular file", path)
	case !errors.Is(err, fs.ErrNotExist):
		return true, fmt.Errorf("read the gateway run mark %s: %w", path, err)
	}
	if err := publishedSessionCreateMarkFile(path); err != nil && !errors.Is(err, fs.ErrExist) {
		return false, fmt.Errorf("add the gateway run mark %s: %w", path, err)
	}
	if err := publishedSessionSyncDir(filepath.Dir(path)); err != nil {
		return false, fmt.Errorf("flush %s: %w", filepath.Dir(path), err)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return false, fmt.Errorf("the gateway run mark %s is not there after it was added: %v", path, err)
	}
	return false, nil
}

// EndPublishedSessionGatewayRun removes the gateway's run mark for the
// record folder root and flushes its folder: the gateway's last step when
// it stops with nothing owed. A mark that is not there is ended.
func EndPublishedSessionGatewayRun(root string) error {
	path, ok := publishedSessionGatewayRunPath(root)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the gateway run mark %s: %w", path, err)
	}
	return publishedSessionSyncDir(filepath.Dir(path))
}

// publishedSessionGatewayRunEnded reports, for the hook during an outage,
// whether the gateway that wrote the records of root ended cleanly: its run
// mark is not there. A mark that is there, or that cannot be read, is an
// error.
func publishedSessionGatewayRunEnded(root string) error {
	path, ok := publishedSessionGatewayRunPath(root)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	_, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err == nil:
		return errPublishedSessionGatewayRunning
	default:
		return fmt.Errorf("read the gateway run mark %s: %w", path, err)
	}
}

// RevokeAllPublishedSessionKeys ends the key of every account that has a
// folder under the record folder root, the way RevokePublishedSessionKey
// ends one: the gateway runs it when its previous run did not end cleanly,
// or when it could not add its run mark, before any allow it publishes
// carries a key. It returns an error wrapping ErrPublishedSessionKeyAlive
// when a key may still be alive: one that could be neither removed nor
// marked revoked, or a record folder that cannot be listed.
func RevokeAllPublishedSessionKeys(root string) error {
	if _, _, ok := publishedSessionKeyRoot(root); !ok {
		return fmt.Errorf("%w: no protected session record folder %q", ErrPublishedSessionKeyAlive, root)
	}
	names, err := publishedSessionList(filepath.Clean(strings.TrimSpace(root)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: list %s: %v", ErrPublishedSessionKeyAlive, root, err)
	}
	var errs []error
	for _, name := range names {
		if !publishedSessionDigest(name) {
			continue
		}
		if err := revokePublishedSessionAccountKey(root, name); err != nil {
			errs = append(errs, fmt.Errorf("account folder %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
