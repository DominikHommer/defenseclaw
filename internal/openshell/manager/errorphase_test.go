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

package manager

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// OpenShell 0.1.5 stops a sandbox in its error state, and starts it again
// after (NVIDIA/OpenShell#4231), so the way on keeps the sandbox; an older
// gateway refuses both, and the way on deletes it.
func TestErrorPhaseWayOnFollowsTheGatewayRelease(t *testing.T) {
	for _, mode := range []string{config.OpenShellWorkdirCopy, ""} {
		old := errorPhaseWayOn("box", mode, "", false)
		if !strings.Contains(old, "neither stop nor start") || !strings.Contains(old, "`defenseclaw sandbox delete box") {
			t.Errorf("%q before 0.1.5: %q", mode, old)
		}
		now := errorPhaseWayOn("box", mode, "", true)
		if strings.Contains(now, "delete") || !strings.Contains(now, "`defenseclaw sandbox stop box` and `defenseclaw sandbox start box`") {
			t.Errorf("%q from 0.1.5: %q", mode, now)
		}
	}
	if got := errorPhaseWayOn("box", "", overlayDiskFullText, true); got != overlayDiskWayOn("box") {
		t.Errorf("a full disk: %q", got)
	}
}
