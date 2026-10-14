//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	darwinID           = "/usr/bin/id"
	darwinDSMemberUtil = "/usr/bin/dsmemberutil"
	// osUserGroupBuffer is the number of groups os/user lists into on macOS. A
	// list that fills it may be cut short.
	osUserGroupBuffer = 256
)

// platformAccountGroupIDs gets candidate gids from os/user, or id when its
// fixed buffer is full, then confirms every supplementary membership against
// the account's uid. Both candidate providers calculate groups by name; Open
// Directory's uid membership check binds each group to the account instead.
func platformAccountGroupIDs(ctx context.Context, runner commandRunner, account *user.User, ids []string, listErr error) ([]string, error) {
	if listErr != nil || len(ids) >= osUserGroupBuffer {
		if err := validName(account.Username); err != nil {
			return nil, errors.Join(listErr, err)
		}
		if err := validateTrustedTool(darwinID); err != nil {
			return nil, errors.Join(listErr, err)
		}
		result, err := runner(ctx, darwinID, []string{"-G", "--", account.Username})
		if err != nil {
			return nil, errors.Join(listErr, err)
		}
		if result.exitCode != 0 {
			return nil, errors.Join(listErr, fmt.Errorf("unixidentity: id exited %d", result.exitCode))
		}
		ids, err = parseIDGroupList(string(result.stdout))
		if err != nil {
			return nil, errors.Join(listErr, err)
		}
	}
	return uidVerifiedGroupIDs(ctx, runner, account, ids)
}

// uidVerifiedGroupIDs checks candidates through the Open Directory
// membership API. The account's primary gid is held by its uid record.
func uidVerifiedGroupIDs(ctx context.Context, runner commandRunner, account *user.User, candidates []string) ([]string, error) {
	uid, err := parseID(account.Uid, "uid")
	if err != nil {
		return nil, err
	}
	primary, err := parseID(account.Gid, "gid")
	if err != nil {
		return nil, err
	}
	if err := validateTrustedTool(darwinDSMemberUtil); err != nil {
		return nil, err
	}
	ids := []int{primary}
	for _, value := range candidates {
		gid, err := parseID(value, "gid")
		if err != nil {
			return nil, err
		}
		if gid != primary {
			ids = append(ids, gid)
		}
	}
	if len(ids) > maxDirectoryGroups {
		return nil, fmt.Errorf("in %d groups, more than the %d DefenseClaw names", len(ids), maxDirectoryGroups)
	}
	verified := make([]bool, len(ids))
	verified[0] = true
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	g, groupCtx := errgroup.WithContext(ctx)
	g.SetLimit(16)
	for i := 1; i < len(ids); i++ {
		i, gid := i, ids[i]
		g.Go(func() error {
			result, err := runner(groupCtx, darwinDSMemberUtil, []string{"checkmembership", "-u", strconv.Itoa(uid), "-g", strconv.Itoa(gid)})
			if err != nil {
				return err
			}
			if result.exitCode != 0 {
				return fmt.Errorf("unixidentity: dsmemberutil exited %d", result.exitCode)
			}
			switch strings.TrimSpace(string(result.stdout)) {
			case "user is a member of the group":
				verified[i] = true
			case "user is not a member of the group":
			default:
				return fmt.Errorf("unixidentity: dsmemberutil returned no membership answer")
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	var out []string
	seen := map[int]bool{}
	for i, gid := range ids {
		if verified[i] && !seen[gid] {
			out = append(out, strconv.Itoa(gid))
			seen[gid] = true
		}
	}
	return out, nil
}

// parseIDGroupList parses the space-separated gids `id -G` prints, once each.
// An account in more than maxDirectoryGroups groups is an error, as on Linux:
// part of a membership must not select a profile.
func parseIDGroupList(output string) ([]string, error) {
	fields := strings.Fields(output)
	if len(fields) > maxDirectoryGroups {
		return nil, fmt.Errorf("in %d groups, more than the %d DefenseClaw names", len(fields), maxDirectoryGroups)
	}
	seen := map[int]bool{}
	var ids []string
	for _, field := range fields {
		gid, err := parseID(field, "gid")
		if err != nil {
			return nil, err
		}
		if !seen[gid] {
			seen[gid] = true
			ids = append(ids, strconv.Itoa(gid))
		}
	}
	if len(ids) == 0 {
		return nil, errors.New("unixidentity: id listed no groups")
	}
	return ids, nil
}
