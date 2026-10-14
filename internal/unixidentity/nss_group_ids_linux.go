//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"errors"
	"fmt"
	"os"
)

func (r *NSSResolver) platformGroupIDs(account Account) ([]int, error) {
	local, err := LocalAccounts(r.context())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if uid, ok := local[account.Name]; ok && uid == account.UID {
		ids, _, err := localAccountGroups(account)
		return ids, err
	} else if ok {
		return r.groupIDsInOwnerService(account)
	}
	// A name may resolve to a different account than the uid did. In that
	// case initgroups must be asked through the service that owns the uid.
	named, nameErr := r.LookupUser(account.Name)
	var mismatch *NameMismatchError
	if nameErr == nil && named.UID != account.UID || errors.As(nameErr, &mismatch) {
		return r.groupIDsInOwnerService(account)
	}
	if nameErr != nil && !IsNotFound(nameErr) {
		return nil, nameErr
	}
	return r.rawGroupIDs(account)
}

// groupIDsInOwnerService resolves an overlapping name only in the directory
// service that independently confirms both the uid and the name.
func (r *NSSResolver) groupIDsInOwnerService(account Account) ([]int, error) {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("unixidentity: read NSS configuration: %w", err)
	}
	for _, service := range ParseNSSwitchServices(string(data), "passwd") {
		if _, known := directoryServices[service]; !known {
			continue
		}
		owner, err := r.LookupUIDInService(service, account.UID)
		if IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		byName, err := r.LookupUserInService(service, account.Name)
		if err != nil {
			return nil, err
		}
		if owner.UID != account.UID || byName.UID != account.UID {
			return nil, fmt.Errorf("unixidentity: account name and uid resolve to different users in %s", service)
		}
		result, err := r.runner(r.context(), r.path, []string{"-s", service, "initgroups", account.Name})
		if err != nil {
			return nil, err
		}
		if result.exitCode == getentExitNotFound {
			return nil, ErrNotFound
		}
		if result.exitCode != getentExitOK {
			return nil, fmt.Errorf("unixidentity: getent -s %s initgroups %s exited %d", service, account.Name, result.exitCode)
		}
		ids, err := ParseInitgroups(string(result.stdout), account.Name)
		if err != nil {
			return nil, err
		}
		return withPrimary(ids, account.GID), nil
	}
	return nil, fmt.Errorf("unixidentity: no NSS service confirms uid %d for %s", account.UID, account.Name)
}
