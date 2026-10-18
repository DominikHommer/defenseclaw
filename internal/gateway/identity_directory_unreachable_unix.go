// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// directoryUnreachable reports whether the hook guardian lists domain ("":
// any domain) as away, in a current, trusted record of its identity spool:
// on a Mac a domain none of whose domain controllers answers (GAP-0092), on
// Linux an SSSD domain SSSD reports offline (GAP-0191). Tests replace it.
var directoryUnreachable = func(domain string) bool {
	domains := enterprisehooks.ReadDirectoryUnreachable(currentIdentitySpoolDir(), validateManagedGuardianAuthorization, time.Now())
	if domain == "" {
		return len(domains) > 0
	}
	return slices.Contains(domains, domain)
}
