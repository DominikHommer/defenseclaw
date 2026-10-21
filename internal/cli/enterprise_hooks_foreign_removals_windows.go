//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseForeignHookSessionTrust is the trust the hook gives the
// protected session records: SYSTEM, Administrators and the gateway service
// account of the standalone layout.
func enterpriseForeignHookSessionTrust(layout managed.StandaloneLayout) (enterprisepolicy.PublishedSessionTrust, error) {
	if strings.TrimSpace(layout.ServiceUser) == "" {
		return enterprisepolicy.PublishedSessionTrust{}, errors.New("the standalone layout names no gateway service account")
	}
	return enterprisepolicy.PublishedSessionTrust{ServiceAccount: layout.ServiceUser}, nil
}
