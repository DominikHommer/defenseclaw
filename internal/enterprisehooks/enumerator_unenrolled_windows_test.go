// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"strings"
	"testing"
)

func TestWindowsUnenrolledClaudeConsequenceFollowsPolicyPublication(t *testing.T) {
	previous := windowsClaudeMachinePolicyPublished
	t.Cleanup(func() { windowsClaudeMachinePolicyPublished = previous })

	windowsClaudeMachinePolicyPublished = func() bool { return false }
	withoutPolicy := windowsUnenrolledConsequence("claudecode")
	if !strings.Contains(withoutPolicy, "without DefenseClaw hooks") ||
		strings.Contains(withoutPolicy, "refuse") {
		t.Fatalf("unpublished Claude Code consequence = %q", withoutPolicy)
	}

	windowsClaudeMachinePolicyPublished = func() bool { return true }
	withPolicy := windowsUnenrolledConsequence("claudecode")
	if !strings.Contains(withPolicy, "refuse this user's tool calls until it is enrolled") {
		t.Fatalf("published Claude Code consequence = %q", withPolicy)
	}
}
