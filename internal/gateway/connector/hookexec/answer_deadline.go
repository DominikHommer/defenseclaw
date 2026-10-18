// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// hookAnswerBudget is how long, from the start of the hook process, a tool
// call's hook waits for its gateway's decision. Every wait of the call
// counts against it: a restart (gatewayRestartBudget), a dial, a gateway that
// accepted the call but does not answer (it is stopping, it is starting, or
// it is so busy that the call waits for its turn), and the resends after a
// 429 or a 401. When the budget ends the call fails: closed for a managed
// hook whatever its fail mode, the account's fail mode for a per-user hook
// (closed unless the account chose open). It is never allowed because the
// gateway was slow. The agent's own tool call then waits at most about four
// seconds plus the launch of the hook, inside the five seconds a tool call
// may wait for DefenseClaw (GAP-0155, GAP-0167, GAP-0139, GAP-0160).
//
// A gateway that waits on a remote scanner for the call (Cisco AI Defense,
// the LLM judge) says so with an informational 102 response
// (HookProgressHeader); the call then keeps the hook's whole budget, since
// such a scanner may take several seconds.
var hookAnswerBudget = 4 * time.Second

// HookProgressHeader asks the gateway to answer 102 Processing as soon as a
// tool call it evaluates waits on a remote scanner. Only hooks that bound
// their wait by hookAnswerBudget send it, so other clients never see an
// informational response.
const HookProgressHeader = "X-DefenseClaw-Hook-Progress"

// HookProgressStatus is the informational status of that report.
const HookProgressStatus = http.StatusProcessing

// errGatewayNoAnswer ends a tool call's hook request whose gateway gave no
// decision, and no progress report, within hookAnswerBudget.
var errGatewayNoAnswer = errors.New("the gateway did not answer within the hook's answer budget")

// managedGatewayNoAnswerReason is the hook-failure reason of a managed hook
// whose gateway gave no decision within hookAnswerBudget.
const managedGatewayNoAnswerReason = "enterprise_managed_gateway_no_answer"

// ManagedGatewayNoAnswerReason is managedGatewayNoAnswerReason for callers
// that render the reason themselves.
const ManagedGatewayNoAnswerReason = managedGatewayNoAnswerReason

// ErrManagedGatewayNoAnswer is wrapped by a managed hook transport error
// (ExchangeForeignHookSession) that the answer budget ended.
var ErrManagedGatewayNoAnswer = errGatewayNoAnswer

// ManagedGatewayNoAnswer reports an error from a managed hook transport that
// the answer budget of a tool call ended.
func ManagedGatewayNoAnswer(err error) bool {
	return errors.Is(err, errGatewayNoAnswer)
}

// perUserGatewayNoAnswerReason is the hook-failure reason of a per-user hook
// whose gateway gave no decision within hookAnswerBudget.
const perUserGatewayNoAnswerReason = "gateway did not answer in time"

// answerDeadline is when the hook of a tool call that started at startedAt
// stops waiting for its gateway; zero (the hook's whole budget, as before)
// for a Secure Client hook and for every event that does not gate a tool
// call. Prompts, session events and stop events keep their budgets: their
// local work (component scans at a stop, for example) can take longer, and
// they do not hold a tool call.
func answerDeadline(opts Options, startedAt time.Time) time.Time {
	if opts.SecureClient || startedAt.IsZero() || !toolGateEvent(opts.Connector, opts.Event) {
		return time.Time{}
	}
	return startedAt.Add(hookAnswerBudget)
}

// toolGateEvent reports a hook event that runs before a tool call (or asks
// for its permission) and blocks it until the hook answers.
func toolGateEvent(connector, event string) bool {
	event = strings.TrimSpace(event)
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "claudecode", "codex", "devin", "kiro", "omnigent", "antigravity":
		return event == "PreToolUse" || event == "PermissionRequest"
	case "copilot":
		return event == "preToolUse" || event == "permissionRequest"
	case "cursor":
		switch strings.ToLower(event) {
		case "pretooluse", "beforeshellexecution", "beforemcpexecution", "beforereadfile", "beforetabfileread":
			return true
		}
	case "hermes":
		return event == "pre_tool_call"
	case "opencode":
		return event == "tool.execute.before"
	case "amp":
		return event == "tool.call"
	}
	return false
}

// awaitAnswerBy returns ctx for the hook request of a tool call, ended with
// errGatewayNoAnswer at deadline unless the gateway answered (stop) or
// reported that it waits on a remote scanner (a 102 response) by then. Call
// stop once the final response headers are in, before reading the body, and
// release when the request is done. A zero deadline returns ctx unchanged.
func awaitAnswerBy(ctx context.Context, deadline time.Time) (watched context.Context, stop, release func()) {
	if deadline.IsZero() {
		return ctx, func() {}, func() {}
	}
	answered := make(chan struct{})
	var once sync.Once
	stop = func() { once.Do(func() { close(answered) }) }
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
		if code == HookProgressStatus {
			stop()
		}
		return nil
	}}
	watched, cancel := context.WithCancelCause(httptrace.WithClientTrace(ctx, trace))
	go func() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-timer.C:
			select {
			case <-answered:
			default:
				cancel(errGatewayNoAnswer)
			}
		case <-answered:
		case <-watched.Done():
		}
	}()
	return watched, stop, func() { stop(); cancel(nil) }
}

// gatewayNoAnswer reports a request ctx that awaitAnswerBy ended.
func gatewayNoAnswer(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errGatewayNoAnswer)
}

// failNoAnswer fails a tool call whose gateway gave no decision in time:
// closed for a managed hook, the fail mode for a per-user hook.
func failNoAnswer(opts Options, sp spec, failMode string) int {
	if opts.ManagedEnterprise {
		return failUnreachable(opts, sp, "closed", managedGatewayNoAnswerReason)
	}
	return failUnreachable(opts, sp, failMode, perUserGatewayNoAnswerReason)
}

// retryFitsAnswer reports whether a resend that starts after delay still
// starts before the answer deadline (always, without one).
func retryFitsAnswer(deadline time.Time, delay time.Duration) bool {
	return deadline.IsZero() || time.Now().Add(delay).Before(deadline)
}
