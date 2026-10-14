//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"reflect"
	"sync"
	"testing"
)

// GAP-0528: macOS lists an account's groups by name (getgrouplist), and the
// list leaves out a group the account is in only through another group: on
// the lab Mac id -Gn named DCLAB\dc-r102-nested for eng2 but not
// DCLAB\dc-r102-devs, which dsmemberutil checkmembership confirmed. The
// groups profile assignments select by are now checked by uid too, so eng2
// gets the devs profile as SSSD gives it on Linux. A directory account named
// like a local one, whose name-based list is the local account's, gets its
// own memberships of those groups the same way.
func TestDarwinNamedGroupsAddVerifiedNestedMemberships(t *testing.T) {
	if err := validateTrustedTool(darwinDSMemberUtil); err != nil {
		t.Skip(err)
	}
	previous := lookupNamedGroupGID
	t.Cleanup(func() { lookupNamedGroupGID = previous })
	groups := map[string]int{"dc-devs": 7000, `CORP\dc-admins`: 7100}
	var looked []string
	lookupNamedGroupGID = func(name string) (int, bool, error) {
		looked = append(looked, name)
		gid, ok := groups[name]
		return gid, ok, nil
	}
	member := map[string]bool{"80002:7001": true, "80002:7000": true, "80001:7000": true, "2100:80": true}
	var mu sync.Mutex
	checked := map[string]int{}
	run := func(_ context.Context, path string, args []string, _ ...outputFilter) (commandResult, error) {
		if path != darwinDSMemberUtil || len(args) != 5 || args[0] != "checkmembership" || args[1] != "-u" || args[3] != "-g" {
			return commandResult{}, fmt.Errorf("unexpected command %q %q", path, args)
		}
		mu.Lock()
		checked[args[2]+":"+args[4]]++
		mu.Unlock()
		if member[args[2]+":"+args[4]] {
			return commandResult{stdout: []byte("user is a member of the group\n")}, nil
		}
		return commandResult{stdout: []byte("user is not a member of the group\n")}, nil
	}
	named := []string{"dc-devs", "DC-DEVS", `CORP\dc-admins`, "dc-devs@corp.example.com", "dc-gone", " "}
	eng2 := &user.User{Username: "eng2", Uid: "80002", Gid: "5000"}

	without, err := platformAccountGroupIDs(context.Background(), run, eng2, []string{"5000", "7001"}, nil, nil)
	if err != nil || !reflect.DeepEqual(without, []string{"5000", "7001"}) {
		t.Fatalf("groups without named groups = %v, %v", without, err)
	}
	got, err := platformAccountGroupIDs(context.Background(), run, eng2, []string{"5000", "7001", "7000"}, nil, named)
	if err != nil || !reflect.DeepEqual(got, []string{"5000", "7001", "7000"}) {
		t.Fatalf("groups listing the nested group already = %v, %v", got, err)
	}
	if checked["80002:7000"] != 1 {
		t.Fatalf("a listed group that is also named was checked %d times, want once", checked["80002:7000"])
	}
	looked = nil
	got, err = platformAccountGroupIDs(context.Background(), run, eng2, []string{"5000", "7001"}, nil, named)
	if err != nil || !reflect.DeepEqual(got, []string{"5000", "7001", "7000"}) {
		t.Fatalf("groups with the named groups = %v, %v; want the nested dc-devs confirmed by uid", got, err)
	}
	if want := []string{"dc-devs", `CORP\dc-admins`, "dc-gone"}; !reflect.DeepEqual(looked, want) {
		t.Fatalf("looked up %q; want %q: each named group once, no UPN form and no blank", looked, want)
	}

	// The directory alex shares the local alex's short name, so the
	// name-based list is the local account's (80). Only memberships the
	// directory uid holds are listed.
	alex := &user.User{Username: "alex", Uid: "80001", Gid: "5000"}
	got, err = platformAccountGroupIDs(context.Background(), run, alex, []string{"20", "80"}, nil, []string{"dc-devs"})
	if err != nil || !reflect.DeepEqual(got, []string{"5000", "7000"}) {
		t.Fatalf("directory namesake groups = %v, %v; want its primary group and its own dc-devs", got, err)
	}

	lookupNamedGroupGID = func(string) (int, bool, error) { return 0, false, errors.New("opendirectoryd did not answer") }
	if got, err := platformAccountGroupIDs(context.Background(), run, eng2, []string{"5000", "7001"}, nil, []string{"dc-devs"}); err == nil {
		t.Fatalf("a named group lookup that failed listed %v; want the listing to fail", got)
	}
}
