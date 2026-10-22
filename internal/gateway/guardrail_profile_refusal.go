// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A Refused profile decision (profileDecision.Refused).
//
// An agents entry that may be a request agent's 1.0.3 identity, which the
// agent ledger does not prove, leaves more than one profile that may apply
// (matchAgent). When none of them enforces at least what each of the
// others does (profileCovers), no single profile is safe to apply: the
// request is refused wherever its surface can block it, on the connector
// hook, the inspect endpoints, ACP and the guardrail proxy. What a surface
// cannot block (an event the agent does not let a hook stop) is decided by
// the strictest of them by hook mode and block_at. The refusal holds until
// the ledger proves whose entry it is or the entry names the agent's
// current identity. Remove with agentidentity.LegacyAgentID.

// profileRefusedReason is what a refused request tells the agent and its
// user.
const profileRefusedReason = "DefenseClaw refused this request: a guardrail profile assignment names an agent identity from before the upgrade " +
	"that cannot be matched to this account, and the profiles that may apply enforce different rules. " +
	"Ask your administrator to replace the entry with the agent identity `defenseclaw agent identities` shows now."

// profileRefused is why ctx's profile decision is Refused, or "".
func (a *APIServer) profileRefused(ctx context.Context) string {
	if resolved := a.resolvedProfile(ctx); resolved != nil {
		return resolved.decision.Refused
	}
	return ""
}

// refuseProfileHook answers a hook whose profile decision is Refused with a
// block, rendered for the agent, where the connector honours one on the
// event. Any other hook is evaluated as usual.
func (a *APIServer) refuseProfileHook(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
) (resp agentHookResponse, refused bool) {
	reason := a.profileRefused(ctx)
	if reason == "" {
		return agentHookResponse{}, false
	}
	action, wouldBlock := mapHookActionForProfile("block", "action", req.HookEventName, profile.Capabilities, profile, payload)
	if action != "block" {
		return agentHookResponse{}, false
	}
	resp = agentHookResponse{
		Action: "block", RawAction: "block", Severity: "HIGH", Mode: "action",
		WouldBlock: wouldBlock, Reason: reason,
	}
	refused = true
	defer func() {
		if recovered := recover(); recovered != nil {
			// resp stays the bare block.
			a.handleHookPanic(ctx, connectorName, req.HookEventName, fmt.Sprintf("profile refusal render panic: %v", recovered))
		}
	}()
	resp = a.renderSandboxVerdict(ctx, profile, req, rawBody, payload, resp, reason)
	return resp, refused
}

// refuseProfileInspect answers an inspect request whose profile decision is
// Refused with a block verdict, audited as action on route, and reports
// whether it did. Each inspect handler calls it, so a sandbox relay of the
// request, which does not pass the inspect middleware, is refused too.
func (a *APIServer) refuseProfileInspect(w http.ResponseWriter, r *http.Request, route, action, target string) bool {
	reason := a.profileRefused(r.Context())
	if reason == "" {
		return false
	}
	fmt.Fprintf(os.Stderr, "[inspect] REFUSED %s: no guardrail profile is safe for the request (unproven identity)\n", route)
	if a.logger != nil {
		_ = a.logger.LogEventCtx(r.Context(), a.inspectAuditEvent(r, route, action, target,
			"severity=HIGH mode=action reason=guardrail_profile_refused"))
	}
	a.writeJSON(w, http.StatusOK, &ToolInspectVerdict{
		Action: "block", RawAction: "block", Severity: "HIGH", Confidence: 1,
		Reason: reason, Findings: []string{}, Mode: "action",
	})
	return true
}

// refuseProfileProxy answers a proxied model request whose profile decision
// is Refused and reports whether it did.
func refuseProfileProxy(w http.ResponseWriter, r *http.Request) bool {
	reason := profileRefusal(r.Context())
	if reason == "" {
		return false
	}
	fmt.Fprintf(os.Stderr, "[guardrail] REFUSED %s: no guardrail profile is safe for the request (unproven identity)\n", r.URL.Path)
	writeOpenAIError(w, http.StatusForbidden, reason)
	return true
}
