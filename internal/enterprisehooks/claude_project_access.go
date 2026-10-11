// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
)

// A refused access check removes the entire project, including local-scope
// definitions already parsed from .claude.json. A missing .mcp.json keeps
// local-scope definitions. Other read failures retain the account-wide
// unreadable marker so a stale inventory cannot be published.
type claudeProjectReadDecision uint8

const (
	claudeProjectKeep claudeProjectReadDecision = iota
	claudeProjectRefused
	claudeProjectUnreadable
)

func decideClaudeProjectRead(accessErr, readErr error) claudeProjectReadDecision {
	if accessErr != nil {
		return claudeProjectRefused
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return claudeProjectUnreadable
	}
	return claudeProjectKeep
}
