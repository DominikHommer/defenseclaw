// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// The standalone enumerator is told which agent sessions run now, so a
// running agent of an enabled connector that no row enrolls is recorded as
// unprotected and status and verify stop saying security_complete. Without
// it a Codex the discovery could not read (GAP-0226: the install.ps1 layout)
// ran without DefenseClaw hooks while every report was green.

// enterpriseWindowsEnumerateRunningLookupTimeout bounds one account lookup,
// and enterpriseWindowsEnumerateRunningLookupBudget all of one cycle, so an
// unreachable domain controller cannot stall the cycle.
var (
	enterpriseWindowsEnumerateRunningLookupTimeout = 3 * time.Second
	enterpriseWindowsEnumerateRunningLookupBudget  = 10 * time.Second
)

// Seams for the running agents and the account lookup; tests replace them.
var (
	enterpriseWindowsEnumerateAgentProcesses = inventory.RunningWindowsAgentProcesses
	enterpriseWindowsEnumerateAccountSID     = func(account string) string {
		sid, _, _, err := windows.LookupSID("", account)
		if err != nil || sid == nil {
			return ""
		}
		return sid.String()
	}
)

// enterpriseWindowsEnumerateRunningAgents returns, by account SID and
// connector, a label of one running agent session ("codex (pid 4242)").
func enterpriseWindowsEnumerateRunningAgents(stderr io.Writer) map[string]map[string]string {
	processes, err := enterpriseWindowsEnumerateAgentProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN running agent sessions are unreadable this cycle; only installs are checked for unenrolled agents: %v\n", err)
		return nil
	}
	out := map[string]map[string]string{}
	sids := map[string]string{}
	var spent time.Duration
	for _, process := range processes {
		user := strings.TrimSpace(process.User)
		connector := strings.ToLower(strings.TrimSpace(process.Connector))
		if user == "" || connector == "" {
			continue
		}
		key := strings.ToLower(user)
		sid, resolved := sids[key]
		if !resolved {
			started := time.Now()
			sid = enterpriseWindowsEnumerateLookupWithin(user, enterpriseWindowsEnumerateRunningLookupBudget-spent)
			spent += time.Since(started)
			sids[key] = sid
		}
		if sid == "" {
			continue
		}
		if out[sid] == nil {
			out[sid] = map[string]string{}
		}
		if _, seen := out[sid][connector]; !seen {
			out[sid][connector] = fmt.Sprintf("%s (pid %d)", connector, process.PID)
		}
	}
	return out
}

// enterpriseWindowsEnumerateLookupWithin resolves account to its SID, or ""
// when the lookup fails or does not answer within the remaining budget.
func enterpriseWindowsEnumerateLookupWithin(account string, remaining time.Duration) string {
	if remaining <= 0 {
		return ""
	}
	if remaining > enterpriseWindowsEnumerateRunningLookupTimeout {
		remaining = enterpriseWindowsEnumerateRunningLookupTimeout
	}
	done := make(chan string, 1)
	lookup := enterpriseWindowsEnumerateAccountSID
	go func() { done <- strings.TrimSpace(lookup(account)) }()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case sid := <-done:
		return sid
	case <-timer.C:
		return ""
	}
}
