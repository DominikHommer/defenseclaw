// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// lifecycleGatewayPolicy is not wired on Windows yet (the Windows bundle
// lifecycle is a later stack item): bundle status warns gateway_unchecked.
func lifecycleGatewayPolicy(context.Context) *enterprisestatus.PolicyState { return nil }
