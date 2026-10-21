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

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestSandboxDaemonKeepsTheGatewayForComputeThatMayStillRun: the daemon
// stops the account's OpenShell gateway, or exits for a pending restart
// (the managed pin migration's, for one), only once no sandbox may hold
// compute: a MicroVM in OpenShell's error state counts, since nothing can
// flush it first; a docker sandbox in that state is a stopped container.
func TestSandboxDaemonKeepsTheGatewayForComputeThatMayStillRun(t *testing.T) {
	for _, tc := range []struct {
		list []sandboxapi.Sandbox
		want int
	}{
		{[]sandboxapi.Sandbox{{Phase: "ready", Driver: "vm"}, {Phase: "stopped", Driver: "vm"}}, 1},
		{[]sandboxapi.Sandbox{{Phase: "error", Driver: "vm"}}, 1},
		{[]sandboxapi.Sandbox{{Phase: "error", Driver: "docker"}, {Phase: "error"}}, 0},
		{[]sandboxapi.Sandbox{{Phase: "stopping", Driver: "vm"}, {Phase: "creating", Driver: "docker"}}, 2},
		{[]sandboxapi.Sandbox{{Phase: "stopped"}, {Phase: "completed"}, {Phase: "deleting", Driver: "vm"}}, 0},
	} {
		if got := sandboxesHoldingCompute(tc.list); got != tc.want {
			t.Errorf("%+v: %d, want %d", tc.list, got, tc.want)
		}
	}
}
