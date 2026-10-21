// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The bundle limits are documented in the command help, not on the public
// site, so each verb must name the codes an operator will see.
func TestEnterpriseBundleHelpNamesTheLimits(t *testing.T) {
	cases := []struct {
		verb string
		cmd  *cobra.Command
		want []string
	}{
		{"verify", newEnterpriseBundleVerifyCommand(), []string{"floor_unchecked", "retired or revoked"}},
		{"status", newEnterpriseBundleStatusCommand(), []string{"gateway_unchecked", "last 20 receipts"}},
		{"apply", newEnterpriseBundleApplyCommand(), []string{"superseded", "bundle_state_unreadable"}},
	}
	for _, c := range cases {
		for _, w := range c.want {
			if !strings.Contains(c.cmd.Long, w) {
				t.Errorf("bundle %s help does not mention %q", c.verb, w)
			}
		}
	}
}
