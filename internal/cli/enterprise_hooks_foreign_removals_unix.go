//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseForeignHookSessionTrust is the trust the hook gives the
// protected session records: root and the gateway service uid that the
// guardian renders into the hook (the runtime descriptor's).
func enterpriseForeignHookSessionTrust(managed.StandaloneLayout) (enterprisepolicy.PublishedSessionTrust, error) {
	_, serviceUID, err := enterpriseHookStandaloneHookTransport()
	if err != nil {
		return enterprisepolicy.PublishedSessionTrust{}, err
	}
	return enterprisepolicy.PublishedSessionTrust{ServiceUID: serviceUID}, nil
}
