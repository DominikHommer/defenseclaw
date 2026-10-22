// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sandboxcli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The first session counted leases before opening its copy review. Another
// terminal attached while the question was open; completion must count it
// again before any stop or deletion.
func TestCopyReviewCompletionKeepsNewlyAttachedSession(t *testing.T) {
	for _, remove := range []bool{false, true} {
		ta := newTestApp(t, "")
		sb := sampleSandbox("review-box")
		sb.Phase = "ready"
		sb.WorkdirMode = config.OpenShellWorkdirCopy
		ta.daemon.add(sb)
		s := session{app: ta.App, api: ta.daemon.client(), sb: &sb, started: true, rm: remove}
		// This is the count taken before the first terminal's review prompt.
		s.others = ta.attachedSessions(sb.Name)
		release := ta.holdSession(sb.Name)
		if err := s.finish(bg, false); err != nil {
			release()
			t.Fatal(err)
		}
		release()
		if ta.calls("POST", sb.Name+"/stop") != 0 || ta.calls("DELETE", sb.Name) != 0 ||
			!strings.Contains(ta.output(), "other session is attached") {
			t.Fatalf("review completion stopped a new session (rm=%v): calls=%v, output=%s", remove, ta.daemon.calls, ta.output())
		}
	}
}
