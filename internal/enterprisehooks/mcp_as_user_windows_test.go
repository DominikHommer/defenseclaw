// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
	"golang.org/x/sys/windows"
)

// #1164: the enumerator refuses, before it takes any token, a request for an
// account or connector it does not enroll, a record it cannot read, and a
// server whose definition is not the one the gateway scanned; a signed-out
// user is refused with a message that says when the scan runs again. It
// never starts a process for any of them.
func TestWindowsMCPAsUserStarterRefusesBeforeStarting(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	home := `C:\Users\dcw-std1`
	server := config.MCPServerEntry{Name: "notes", Command: "npx", Args: []string{"-y", "."}, Connector: "claudecode", Project: home + `\proj`}
	request, err := mcpasuser.NewRequest("DefenseClawGateway", sid, server)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	manifest := Manifest{Targets: []ManifestTarget{
		{User: "dcw-std1", UserHome: home, SID: sid, Connector: "claudecode", Enabled: &enabled},
		{User: "dcw-std2", UserHome: `C:\Users\dcw-std2`, SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode", Enabled: &enabled},
	}}
	starter := WindowsMCPAsUserStarter{
		Manifest:         func() (Manifest, error) { return manifest, nil },
		AuthorizationDir: func() (string, error) { return `C:\ProgramData\x`, nil },
	}
	oldSpool, oldToken, oldStart := windowsMCPAsUserReadSpool, windowsMCPAsUserSessionToken, windowsMCPAsUserStartProcess
	t.Cleanup(func() {
		windowsMCPAsUserReadSpool, windowsMCPAsUserSessionToken, windowsMCPAsUserStartProcess = oldSpool, oldToken, oldStart
	})
	published := []config.MCPServerEntry{server}
	var spoolErr error
	var unreadable *ClaudeStateUnreadable
	windowsMCPAsUserReadSpool = func(_, gotSID, connector string) ([]config.MCPServerEntry, *ClaudeStateUnreadable, error) {
		if gotSID != sid || connector != "claudecode" {
			t.Errorf("read the record of %s %s", gotSID, connector)
		}
		return published, unreadable, spoolErr
	}
	tokens := 0
	windowsMCPAsUserSessionToken = func(*windows.SID) (windows.Token, error) {
		tokens++
		return 0, &WindowsTargetSessionUnavailableError{SID: sid}
	}
	windowsMCPAsUserStartProcess = func(windows.Token, []string, []string, string) (mcpasuser.Session, error) {
		t.Fatal("a process was started")
		return nil, nil
	}

	other := request
	other.SID = "S-1-5-21-1-2-3-1003"
	kiro := request
	kiro.Connector = "kiro"
	for name, req := range map[string]mcpasuser.Request{"not enrolled": other, "other connector": kiro} {
		if _, err := starter.Start(context.Background(), req); err == nil || !strings.Contains(err.Error(), "not enrolled") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	spoolErr = errors.New("record missing")
	if _, err := starter.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "record missing") {
		t.Fatalf("unreadable spool: %v", err)
	}
	spoolErr, unreadable = nil, &ClaudeStateUnreadable{Path: home + `\.claude.json`, Reason: "parse"}
	if _, err := starter.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unreadable state: %v", err)
	}
	unreadable = nil
	changed := server
	changed.Args = []string{"-y", "evil"}
	published = []config.MCPServerEntry{changed}
	if _, err := starter.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed definition: %v", err)
	}
	shell := server
	shell.Command, shell.Args = "cmd.exe", []string{"/c", "calc"}
	shellRequest, err := mcpasuser.NewRequest("DefenseClawGateway", sid, shell)
	if err != nil {
		t.Fatal(err)
	}
	published = []config.MCPServerEntry{shell}
	if _, err := starter.Start(context.Background(), shellRequest); err == nil || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("shell server: %v", err)
	}
	if tokens != 0 {
		t.Fatalf("a token was taken for a refused request (%d)", tokens)
	}
	published = []config.MCPServerEntry{server}
	if _, err := starter.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("signed-out user: %v", err)
	}
}
