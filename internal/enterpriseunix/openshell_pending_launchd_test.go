// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestMacOSPendingLaunchAgentAdvice(t *testing.T) {
	h := newOSHost(t, "darwin")
	entry := pending{Kind: "launchd", User: "sample-user", UID: h.alice.UID, Since: "2026-10-14T12:00:00Z", Reason: "the signed gateway binary changed", Sandboxes: 2}
	r := &enterprisestatus.Result{}
	(&lifecycle{env: h.env, result: r}).describePending(entry)
	message := messagesOf(r.Warnings, codeSandboxPending)
	for _, want := range []string{"sudo " + h.env.lifecycleCommand(ActionRepair), "root ensure, repair or reconcile", "first sandbox started after the running ones stop", "reloads the job itself", "If that reload fails, the start reports it"} {
		if !strings.Contains(message, want) {
			t.Fatalf("pending LaunchAgent advice %q misses %q", message, want)
		}
	}
	if strings.Contains(message, "does not apply the reload") || strings.Contains(message, "can fail with a code-signing exit") {
		t.Fatalf("LaunchAgent advice retains the old first-use window: %q", message)
	}

	entry.Kind = "restart"
	r = &enterprisestatus.Result{}
	(&lifecycle{env: h.env, result: r}).describePending(entry)
	want := fmt.Sprintf("pending restart for user sample-user since %s (the signed gateway binary changed): 2 sandboxes run (or are starting, stopping, or a MicroVM whose workload ended that the user has not let go); it is applied by the first run of `%s` or the user's next `defenseclaw sandbox` command that finds no sandbox running. The user's `defenseclaw sandbox stop NAME` flushes and stops a running one, and lets the change stop a MicroVM whose workload completed or that is in OpenShell's error state, which nothing in OpenShell flushes or stops (what it has not written to disk by then is lost); `defenseclaw sandbox delete NAME` deletes one\n",
		entry.Since, h.env.lifecycleCommand(ActionEnsure))
	if got := messagesOf(r.Warnings, codeSandboxPending); got != want {
		t.Fatalf("restart advice changed: got %q, want %q", got, want)
	}
}
