// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

// perUserEnvTightenComment and perUserEnvTightenLine are what a per-user
// shell hook renders after its baked FAIL_MODE: the environment can close it,
// never open it (GAP-0315).
const (
	perUserEnvTightenComment = "# An inherited DEFENSECLAW_FAIL_MODE can only tighten the installed mode:"
	perUserEnvTightenLine    = `case "${DEFENSECLAW_FAIL_MODE:-}" in [Cc][Ll][Oo][Ss][Ee][Dd]) FAIL_MODE="closed" ;; esac`
)
