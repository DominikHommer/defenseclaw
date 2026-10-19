//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// #1201: a standard account refused `enterprise windows sandbox list --user
// X` was told to have an administrator run `enterprise windows list`, which
// does not exist. The refusal names the command's own path and the user.
func TestWindowsEnterpriseAdminViewCommandNamesItsOwnPath(t *testing.T) {
	root := &cobra.Command{Use: "defenseclaw-gateway"}
	enterprise := &cobra.Command{Use: "enterprise"}
	windows := &cobra.Command{Use: "windows"}
	sandbox := &cobra.Command{Use: "sandbox"}
	list := &cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return nil }}
	var user string
	list.Flags().StringVar(&user, "user", "", "")
	identity := &cobra.Command{Use: "profile-explain", RunE: func(*cobra.Command, []string) error { return nil }}
	root.AddCommand(enterprise)
	enterprise.AddCommand(windows)
	windows.AddCommand(sandbox, identity)
	sandbox.AddCommand(list)
	if err := list.Flags().Set("user", "dcw-std1"); err != nil {
		t.Fatal(err)
	}
	what, view, args := windowsEnterpriseAdminViewCommand(list)
	if what != "the sandbox registrations" || view != "enterprise windows sandbox list" ||
		args != "enterprise windows sandbox list --user dcw-std1" {
		t.Fatalf("sandbox list = %q, %q, %q", what, view, args)
	}
	if err := list.Flags().Set("user", `DCLAB\o'brien smith`); err != nil {
		t.Fatal(err)
	}
	if _, _, args := windowsEnterpriseAdminViewCommand(list); args != `enterprise windows sandbox list --user 'DCLAB\o''brien smith'` {
		t.Fatalf("quoted user = %q", args)
	}
	if got := windowsPowerShellArgument(`DCLAB\ent-bob`); got != `DCLAB\ent-bob` {
		t.Fatalf("plain user = %q", got)
	}
	what, view, args = windowsEnterpriseAdminViewCommand(identity)
	if what != "the identity views" || view != "enterprise windows profile-explain" || args != view {
		t.Fatalf("identity view = %q, %q, %q", what, view, args)
	}
}
