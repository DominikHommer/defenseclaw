// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// An SSSD domain that realmd did not join (for example a cloud directory's
// LDAP interface read with id_provider = ldap) still gets a directory type
// from its id provider.
func TestSSSDProviderDirectory(t *testing.T) {
	for provider, want := range map[string]useridentity.Directory{
		"ldap":  useridentity.DirectoryLDAP,
		"ipa":   useridentity.DirectoryLDAP,
		" AD ":  useridentity.DirectoryActiveDirectory,
		"proxy": "",
		"":      "",
	} {
		if got := sssdProviderDirectory(provider); got != want {
			t.Errorf("sssdProviderDirectory(%q) = %q, want %q", provider, got, want)
		}
	}
}

// GAP-0583: InfoPipe is not asked (which would D-Bus-activate sssd-ifp)
// while systemd reports sssd.service other than active; a host whose systemd
// does not answer keeps asking.
func TestInfoPipeWaitsForAnActiveSSSD(t *testing.T) {
	for _, tc := range []struct {
		active, known, refused bool
	}{{false, true, true}, {true, true, false}, {false, false, false}} {
		if err := infoPipeGate(tc.active, tc.known); (err != nil) != tc.refused {
			t.Errorf("infoPipeGate(active=%v, known=%v) = %v, want refused=%v", tc.active, tc.known, err, tc.refused)
		}
	}
}

// GAP-0191: on Linux the guardian asks SSSD (InfoPipe) whether it is online
// for each enrolled account's SSSD domain. Only an answer that SSSD is
// offline makes the domain away: a host whose InfoPipe does not answer is
// never put in an outage.
func TestDirectoryAnswersAsksSSSD(t *testing.T) {
	orig := sssdDomainOnline
	t.Cleanup(func() { sssdDomainOnline = orig })
	for _, tc := range []struct {
		online bool
		err    error
		want   bool
	}{{true, nil, true}, {false, nil, false}, {false, errors.New("sssd_ifp is not running"), true}} {
		var asked string
		sssdDomainOnline = func(ctx context.Context, domain string) (bool, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("InfoPipe asked without a deadline")
			}
			asked = domain
			return tc.online, tc.err
		}
		if got := DirectoryAnswers(context.Background(), "dclab.test"); got != tc.want || asked != "dclab.test" {
			t.Errorf("online %t, err %v: answers = %t (asked %q), want %t", tc.online, tc.err, got, asked, tc.want)
		}
	}
	if !DirectoryAwayWithoutAnswer {
		t.Fatal("SSSD reports its offline state itself: a domain it reports offline is away from the start")
	}
}

// The return flush runs sss_cache only from a root-owned path.
func TestFlushDirectoryCachesNeedsARootOwnedSSSCache(t *testing.T) {
	orig := sssCacheTools
	t.Cleanup(func() { sssCacheTools = orig })
	tool := filepath.Join(t.TempDir(), "sss_cache")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sssCacheTools = []string{tool, filepath.Join(t.TempDir(), "missing")}
	if err := FlushDirectoryCaches(context.Background()); err == nil || !strings.Contains(err.Error(), "root-owned") {
		t.Fatalf("err = %v, want a refusal of a tool that is not root-owned", err)
	}
}
