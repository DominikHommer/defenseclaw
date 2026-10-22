// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type verifiedUserScopedIdentityContextKey struct{}

// handleForeignHookSession keeps the standalone session snapshot in the
// gateway's data directory. The namespace comes only from hook-socket peer
// credentials or a per-user hook token authenticated by tokenAuth.
//
// On a standalone host an exchange holds its account's removal lock shared
// (enterprisepolicy.LockForeignHookAccountExchange) from before it reads the
// record key and the guardian's removals until its answer is written, and
// answers allow only within foreignHookExchangeHold of taking it. A hook
// removal of the account (the guardian holds the lock exclusively) therefore
// either waits for this answer or makes this exchange deny; other accounts
// never wait on it (GAP-0348, GAP-0414).
func (a *APIServer) handleForeignHookSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.userScopedCredentialsRequired() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	connector := strings.TrimPrefix(r.URL.Path, enterprisepolicy.ForeignHookSessionPathPrefix)
	if connector == "" || strings.Contains(connector, "/") || authenticatedHookConnector(r.Context()) != connector {
		writeManagedHookRefusal(w, http.StatusForbidden, "foreign_hook_session_scope_unverified")
		return
	}
	identity := ""
	if peer, ok := managedHookPeerFromContext(r.Context()); ok {
		identity = strconv.Itoa(peer.UID)
	} else {
		identity, _ = r.Context().Value(verifiedUserScopedIdentityContextKey{}).(string)
	}
	if identity == "" {
		writeManagedHookRefusal(w, http.StatusForbidden, "foreign_hook_session_identity_unverified")
		return
	}
	dataDir := strings.TrimSpace(a.configDataDir())
	if !filepath.IsAbs(dataDir) {
		writeManagedHookRefusal(w, http.StatusServiceUnavailable, "foreign_hook_session_store_unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var exchange enterprisepolicy.SessionExchange
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&exchange); err != nil {
		http.Error(w, "invalid session update", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "invalid session update", http.StatusBadRequest)
		return
	}
	if exchange.Key.Connector != connector {
		writeManagedHookRefusal(w, http.StatusForbidden, "foreign_hook_session_scope_mismatch")
		return
	}
	stateDir := enterprisepolicy.ForeignHookSessionStoreDir(dataDir, identity)
	// Each identity has its own store, so only that identity's exchanges
	// are serialized; another account's exchange never waits on this one.
	unlock := sync.OnceFunc(a.foreignHookSessionLocks.lock(stateDir))
	defer unlock()
	places := a.foreignHookSessionPlaces(dataDir)
	// Only a standalone gateway gets here (userScopedCredentialsRequired),
	// so every exchange takes its account's removal lock.
	var lockErr error
	release := func() {}
	ctx, cancel := context.WithTimeout(r.Context(), foreignHookExchangeWait)
	if held, err := foreignHookAccountExchangeLock(ctx, dataDir, identity); err != nil {
		lockErr = err
	} else {
		release = held
	}
	cancel()
	defer release()
	answerBy := time.Now().Add(foreignHookExchangeHold)
	// The record key first, then the guardian's removals, both under the
	// account's lock: a removal rotates the key and records itself while it
	// holds the lock exclusively, so an allow made with the key read here was
	// decided from removals at least as new as that key, and one made with a
	// key read before a removal proves nothing during an outage.
	recordKey := places.key(identity)
	removals, ledgerErr := a.foreignHookRemovals.forIdentity(places.removalsDir, identity)
	removalsErr := errors.Join(lockErr, ledgerErr, places.rootErr)
	if lockErr != nil && errors.Is(lockErr, enterprisepolicy.ErrForeignHookRemovalPending) {
		// A removal in progress has its own reason; join hides it otherwise.
		removalsErr = lockErr
	}
	killed := false
	decision := enterprisepolicy.ApplyForeignHookSession(enterprisepolicy.SessionUpdate{
		StateDir:     stateDir,
		Key:          exchange.Key,
		SessionStart: exchange.SessionStart,
		Decision:     exchange.Decision,
		Removals:     removals,
		RemovalsErr:  removalsErr,
		Now:          time.Now(),
		// A block is recorded in the private store only after the account's
		// key is gone: the block is published only after that write, and a
		// gateway that stops in between, or whose publication fails, must
		// not leave an allow the hook honors during the outage (the kill
		// switch, GAP-0352).
		BeforeBlock: func() { killed = a.killForeignHookSessionKey(places, identity, exchange.Key) },
	})
	if decision.Deny && !killed {
		// Every denial is published only after the key is gone.
		a.killForeignHookSessionKey(places, identity, exchange.Key)
	}
	if !decision.Deny && !time.Now().Before(answerBy) {
		// Too late to answer allow: a removal of the account may already
		// have stopped waiting for this exchange. Nothing is published.
		decision = enterprisepolicy.ApplyForeignHookRemovals(decision, exchange.Key, nil, errForeignHookExchangeExpired, time.Now())
		a.killForeignHookSessionKey(places, identity, exchange.Key)
	}
	// Under the same locks, so the protected record follows the store's
	// order: the hook reads it when the gateway is down.
	a.publishForeignHookSessionDecision(places.recordRoot, identity, exchange.Key, decision, recordKey)
	if decision.Deny {
		// A denial cannot become an allow when the guardian commits a
		// removal, so neither lock is held through the audit export or the
		// response write.
		release()
		unlock()
		a.auditForeignHookSessionDenial(r.Context(), connector, exchange, decision)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decision)
		return
	}
	if refusal := writeFencedForeignHookAllow(w, decision, answerBy); refusal != "" {
		release()
		unlock()
		writeManagedHookRefusal(w, http.StatusServiceUnavailable, refusal)
	}
}

// errForeignHookExchangeExpired is an exchange that could not answer within
// foreignHookExchangeHold of taking its account's removal lock.
var errForeignHookExchangeExpired = errors.New("the exchange did not answer in time")

// foreignHookExchangeWait bounds how long an exchange waits for its
// account's removal lock (enterprisepolicy.ForeignHookExchangeWait),
// foreignHookExchangeHold how long after taking it the exchange may answer
// allow (enterprisepolicy.ForeignHookExchangeHold), and
// foreignHookFencedWriteTimeout an allow's response write, so a client that
// stops reading its response does not hold the lock for long. A response
// that fits the socket buffer is written without the client reading; one the
// client does not take in time is cut, and the client's hook fails closed on
// the incomplete response. foreignHookAccountExchangeLock takes the lock
// (replaceable in tests).
var (
	foreignHookExchangeWait        = enterprisepolicy.ForeignHookExchangeWait
	foreignHookExchangeHold        = enterprisepolicy.ForeignHookExchangeHold
	foreignHookFencedWriteTimeout  = 250 * time.Millisecond
	foreignHookAccountExchangeLock = enterprisepolicy.LockForeignHookAccountExchange
)

// writeFencedForeignHookAllow writes an allow and flushes it to the
// connection within foreignHookFencedWriteTimeout, and never past answerBy.
// It returns a refusal reason, having written nothing, when the connection
// cannot bound the write or answerBy has passed: the caller then refuses the
// call instead of answering an allow that a removal no longer waits for. A
// write cut at the deadline leaves the expired deadline in place, so the
// server's own finishing writes fail at once too.
func writeFencedForeignHookAllow(w http.ResponseWriter, decision enterprisepolicy.GuardDecision, answerBy time.Time) string {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(decision); err != nil {
		return "foreign_hook_response_unbounded"
	}
	deadline := time.Now().Add(foreignHookFencedWriteTimeout)
	if answerBy.Before(deadline) {
		deadline = answerBy
	}
	if !time.Now().Before(deadline) {
		return "foreign_hook_removal_fence_expired"
	}
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(deadline); err != nil {
		return "foreign_hook_response_unbounded"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body.Bytes()); err != nil {
		return ""
	}
	if err := controller.Flush(); err != nil {
		return ""
	}
	// A keep-alive connection serves the caller's next request: clear the
	// deadline only after the whole allow has reached it.
	_ = controller.SetWriteDeadline(time.Time{})
	return ""
}

// foreignHookSessionPublishRoot is the folder of the protected session
// records on a standalone host (managed.StandaloneLayout.HookSessionDir),
// foreignHookSessionRootForDataDir the same folder named by the gateway's
// data directory (managed.StandaloneHookSessionDirForDataDir),
// foreignHookSessionKey reads an account's key
// (enterprisepolicy.ReadPublishedSessionKey), foreignHookSessionPublish
// writes the protected record and foreignHookSessionKill removes an
// account's key (replaceable in tests).
var (
	foreignHookSessionPublishRoot    = standaloneHookSessionDir
	foreignHookSessionRootForDataDir = func(dataDir string) (string, bool) {
		return managed.StandaloneHookSessionDirForDataDir(runtime.GOOS, dataDir)
	}
	foreignHookSessionKey     = enterprisepolicy.ReadPublishedSessionKey
	foreignHookSessionPublish = enterprisepolicy.PublishForeignHookSessionDecision
	foreignHookSessionKill    = enterprisepolicy.KillPublishedSessionKey
)

// foreignHookSessionPlaces are where one exchange reads the guardian's
// removals and writes its protected session record: the guardian's ledger
// folder (managed.HookGuardianAuthorizationDir) and the protected session
// record root ("" where this gateway publishes none). rootErr is a record
// root a standalone gateway
// could not locate at all (foreignHookSessionRecordRoot): the exchange is
// denied, because the gateway can then neither remove the key nor publish
// its answer.
type foreignHookSessionPlaces struct {
	removalsDir string
	recordRoot  string
	rootErr     error
}

func (a *APIServer) foreignHookSessionPlaces(dataDir string) foreignHookSessionPlaces {
	places := foreignHookSessionPlaces{removalsDir: managed.HookGuardianAuthorizationDir(dataDir)}
	root, err := a.foreignHookSessionRecordRoot(dataDir)
	if err != nil {
		places.rootErr = fmt.Errorf("the protected foreign-hook session record folder cannot be located: %w", err)
	} else {
		places.recordRoot = strings.TrimSpace(root)
	}
	return places
}

// key is the account's current record key, or none where there is no record
// folder or the key cannot be read: an allow published without a key proves
// nothing during an outage.
func (p foreignHookSessionPlaces) key(identity string) enterprisepolicy.SessionRecordKey {
	if p.recordRoot == "" {
		return enterprisepolicy.SessionRecordKey{}
	}
	key, err := foreignHookSessionKey(p.recordRoot, identity)
	if err != nil {
		return enterprisepolicy.SessionRecordKey{}
	}
	return key
}

// foreignHookSessionRecordRoot is the protected session record folder of a
// standalone gateway, or "" for Secure Client and per-user gateways, which
// have none. On Linux and macOS the layout is fixed. A lookup of the
// Windows layout that fails (the protected ProgramData registration cannot
// be read for a moment) falls back to the folder this gateway located last,
// and else to the one its data directory names (dataDir), so that an
// exchange still removes the key where the hook reads it. Only when none
// names a folder is it an error.
func (a *APIServer) foreignHookSessionRecordRoot(dataDir string) (string, error) {
	cfg := a.scannerCfg
	if cfg == nil || !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() {
		return "", nil
	}
	root, err := foreignHookSessionPublishRoot()
	if err == nil {
		if root = strings.TrimSpace(root); root != "" {
			a.foreignHookSessionRoot.Store(&root)
		}
		return root, nil
	}
	if last := a.foreignHookSessionRoot.Load(); last != nil {
		return *last, nil
	}
	if fallback, ok := foreignHookSessionRootForDataDir(dataDir); ok {
		return fallback, nil
	}
	return "", err
}

// publishForeignHookSessionDecision writes the answer of one session
// exchange into the caller's protected session records under root, which
// the hook reads during a gateway outage under fail mode open (GAP-0352):
// an allow with a MAC made with recordKey, a denial without one. A failure
// is logged; the account's key was removed before every denial, so a record
// the gateway could not replace proves nothing. Without a root nothing is
// published.
func (a *APIServer) publishForeignHookSessionDecision(root, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey) {
	if root == "" {
		return
	}
	if decision.Deny {
		recordKey = enterprisepolicy.SessionRecordKey{}
	}
	if err := foreignHookSessionPublish(root, identity, key, decision, recordKey, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record for %s was not written (the hook blocks during a gateway outage): %v\n",
			clipForeignHookAuditField(key.Connector, 64), err)
	}
}

// killForeignHookSessionKey removes the account's record key before the
// exchange records a block, and before it publishes any denial (the kill
// switch, GAP-0352): every allow of the account written before proves
// nothing during an outage from then on, until the hook guardian makes a
// new key (it does at every pass). Other accounts keep theirs. A removal
// that fails is logged; the block is still recorded and published, and the
// published block denies during an outage. It reports whether the key is
// gone.
func (a *APIServer) killForeignHookSessionKey(places foreignHookSessionPlaces, identity string, key enterprisepolicy.SessionKey) bool {
	connectorName := clipForeignHookAuditField(key.Connector, 64)
	if places.recordRoot == "" {
		if places.rootErr != nil {
			fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record key for %s could not be removed before a block: %v\n", connectorName, places.rootErr)
		}
		return false
	}
	if err := foreignHookSessionKill(places.recordRoot, identity); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record key for %s could not be removed before a block, so only the published block denies during a gateway outage: %v\n",
			connectorName, err)
		return false
	}
	return true
}

// foreignHookAuditReasonLimit bounds the reason an audit row repeats, and
// foreignHookAuditFieldLimit each finding field (the session store clips
// the same fields to 512 bytes). The caller sends these values, so an
// enrolled user must not be able to write rows of any size.
const (
	foreignHookAuditReasonLimit = 2048
	foreignHookAuditFieldLimit  = 512
)

// foreignHookDenialRuleID is the rule ID every foreign-hook guard denial
// carries. The guard matches no rule pack, so its blocks had action and
// severity but no rule_id on their tool, agent and apply_guardrail spans and
// in Galileo, and a dashboard could not tell them from any other block
// (GAP-2610). The reason stays on the audit row and the hook decision record.
const foreignHookDenialRuleID = "ENTERPRISE-FOREIGN-HOOK-BLOCKED"

// clipForeignHookAuditField drops control characters and bounds value to
// limit bytes on a rune boundary.
func clipForeignHookAuditField(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	return truncateToRuneBoundary(value, limit)
}

// auditForeignHookSessionDenial writes one connector-hook audit row for a
// tool call the foreign-hook guard denies, when the exchange records a
// session block, enforces an earlier one, or denies the call alone, so the
// administrator sees each denial with the connector, the user and the file,
// like other blocks, instead of only the guardian's periodic journal
// summary. The guard's own hook in the agent enforces the decision; this
// row is its record.
func (a *APIServer) auditForeignHookSessionDenial(
	ctx context.Context,
	connectorName string,
	exchange enterprisepolicy.SessionExchange,
	decision enterprisepolicy.GuardDecision,
) {
	if a == nil {
		return
	}
	// The denial names the agent identity (agt-) of the caller like any
	// other hook decision: the verified user and the connector derive it, no
	// session is needed. The rows had the user but no agt- (GAP-1039). The
	// guard keys its block on the agent process, not a session, so an
	// OpenCode denial carries no ais-.
	if facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: connectorName}); facts.ID != "" {
		identity := AgentIdentityFromContext(ctx)
		identity.IdentityID, identity.IdentityVerified = facts.ID, facts.Verified
		ctx = ContextWithAgentIdentity(ctx, identity)
	}
	block := "call"
	switch {
	case strings.Contains(decision.Reason, "cannot verify this agent session's hook record"):
		block = "session_record_unavailable"
	case exchange.SessionStart && exchange.Decision.Deny:
		block = "session_recorded"
	case !exchange.Decision.Deny:
		block = "session_enforced"
	}
	extra := map[string]string{
		"guard":         "foreign_hook_session",
		"session_block": block,
		"findings":      strconv.Itoa(len(decision.Findings)),
	}
	for _, finding := range decision.Findings {
		if finding.Allowed || finding.Path == "" {
			continue
		}
		extra["file"] = clipForeignHookAuditField(finding.Path, foreignHookAuditFieldLimit)
		if finding.Scope != "" {
			extra["scope"] = clipForeignHookAuditField(finding.Scope, foreignHookAuditFieldLimit)
		}
		if finding.Digest != "" {
			extra["digest"] = clipForeignHookAuditField(finding.Digest, foreignHookAuditFieldLimit)
		}
		if finding.Reason != "" {
			extra["finding_reason"] = clipForeignHookAuditField(finding.Reason, foreignHookAuditFieldLimit)
		}
		break
	}
	reason := clipForeignHookAuditField(decision.Reason, foreignHookAuditReasonLimit)
	env := HookAuditEnvelope{
		Connector:  connectorName,
		Event:      "foreign_hook_session",
		Result:     "ok",
		Action:     "block",
		RawAction:  "block",
		Severity:   "HIGH",
		Mode:       "action",
		Reason:     reason,
		RuleIDs:    []string{foreignHookDenialRuleID},
		WouldBlock: true,
		Enforced:   true,
		Extra:      extra,
	}
	// The denial is a guardrail block like any other, so it is exported as
	// one: a hook decision record naming the user, the connector-hook block
	// metrics and an apply_guardrail block span. Before, it reached only the
	// audit row, and dashboards, alerts and traces that count blocks never
	// saw it (GAP-2044).
	a.emitForeignHookSessionDenialV8(ctx, connectorName, exchange, env)
	if a.logger != nil {
		_ = a.logConnectorHookAuditEnvelope(ctx, env)
	}
}

// emitForeignHookSessionDenialV8 exports one foreign-hook guard denial
// through the same v8 families as a connector-hook block.
func (a *APIServer) emitForeignHookSessionDenialV8(
	ctx context.Context,
	connectorName string,
	exchange enterprisepolicy.SessionExchange,
	env HookAuditEnvelope,
) {
	if ctx == nil {
		return
	}
	defer func() { _ = recover() }()
	// The hook event the agent sent names the decision's lifecycle event
	// (tool_start for a tool call), as for any other hook block; without it
	// every denial said lifecycle.event "event" (GAP-2216).
	event := clipForeignHookAuditField(strings.TrimSpace(exchange.Event), foreignHookAuditFieldLimit)
	req := agentHookRequest{
		ConnectorName: connectorName,
		HookEventName: firstNonEmpty(event, env.Event),
		SessionID:     exchange.Key.Session,
	}
	// An enforced block, as a hook response reports it: would_block marks an
	// observe-mode decision only.
	resp := agentHookResponse{
		Action: env.Action, RawAction: env.RawAction, Severity: env.Severity,
		Mode: env.Mode, Reason: env.Reason, RuleIDs: env.RuleIDs,
	}
	a.emitHookDecisionObservabilityV8(ctx, req, resp, env, false)
	// A denied tool call carries the block on its tool span, like any other
	// blocked call, so every trace destination (Galileo included) shows it;
	// a session or prompt event gets an apply_guardrail span named for what
	// was denied, never "tool_call" (GAP-2142).
	targetType, tool := foreignHookSessionDenialTarget(exchange)
	if tool != "" {
		if outcome, ok := hookGuardrailOutcomeFor(resp.Action, resp.Severity, resp.Reason, env.RuleIDs); ok {
			meta := hookLLMEventMeta(ctx, connectorName, exchange.Key.Session, "", "", connectorName, "", "", "", nil)
			meta = applyHookEventMeta(meta, event, nil)
			meta.Guardrail = outcome
			meta.LifecycleOutcome = "blocked"
			a.emitHookToolSpanFor(ctx, meta, tool, "", "", outcome.Reason, nil)
			return
		}
	}
	a.emitGuardrailApplyTraceV8(ctx, connectorName, "", targetType, &ToolInspectVerdict{
		Action: resp.Action, RawAction: resp.RawAction, Severity: resp.Severity,
		Reason: resp.Reason, Mode: resp.Mode,
	}, 0, hookEvaluationContext{RuleIDs: env.RuleIDs})
}

// foreignHookSessionDenialTarget names what a foreign-hook denial was for:
// the apply_guardrail target type, and the tool when the event is a tool
// call. An exchange from a hook that sends no event name keeps the earlier
// "tool_call" label unless it is a session start.
func foreignHookSessionDenialTarget(exchange enterprisepolicy.SessionExchange) (targetType, tool string) {
	event := strings.TrimSpace(exchange.Event)
	if event == "" {
		if exchange.SessionStart {
			return "session", ""
		}
		return "tool_call", ""
	}
	switch canonicalHookLifecycleEvent(event) {
	case "tool_start", "tool_end":
		tool = clipForeignHookAuditField(strings.TrimSpace(exchange.Tool), foreignHookAuditFieldLimit)
		if tool == "" {
			// Cursor's shell, MCP and file events name no tool.
			tool = "tool"
			if strings.EqualFold(event, "beforeShellExecution") {
				tool = "shell"
			}
		}
		return "tool_call", tool
	case "session_start", "session_end", "subagent_start", "subagent_stop":
		return "session", ""
	case "turn_start":
		return "prompt", ""
	case "turn_end":
		return "completion", ""
	case "compact_start", "compact_end":
		return "compaction", ""
	}
	// Cursor's workspaceOpen opens the session and afterAgentThought is
	// agent output; neither is a lifecycle event of its own (GAP-2216).
	switch canonicalEvent(event) {
	case "workspaceopen":
		return "session", ""
	case "afteragentthought":
		return "completion", ""
	}
	if exchange.SessionStart {
		return "session", ""
	}
	if isPromptLikeEvent(event) {
		return "prompt", ""
	}
	return "event", ""
}

// foreignHookRemovalSource reads the guardian's ledger for each call. A
// pending cleanup denial must be visible before its file removal even when
// the replacement ledger has the same size and timestamp as the last one.
type foreignHookRemovalSource struct{}

// forIdentity returns the removals the guardian recorded for one caller.
// A missing ledger records none; one that fails its trust check or does not
// parse is an error, which denies the call.
func (foreignHookRemovalSource) forIdentity(dir, identity string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile)
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	removals, err := readForeignHookRemovals(path)
	if err != nil {
		return nil, err
	}
	var out []enterprisepolicy.ForeignHookRemoval
	for _, removal := range removals {
		if canonical, ok := connector.CanonicalUserScopedIdentity(removal.Identity); ok && canonical == identity {
			out = append(out, removal)
		}
	}
	return out, nil
}

// The guardian replaces the ledger while exchanges run. A read that meets
// the replacement on Windows is tried again foreignHookRemovalsBusyRetries
// times, foreignHookRemovalsBusyDelay apart, well within an exchange's
// hold, instead of denying the call.
const (
	foreignHookRemovalsBusyRetries = 20
	foreignHookRemovalsBusyDelay   = 5 * time.Millisecond
)

func readForeignHookRemovals(path string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	for attempt := 0; ; attempt++ {
		removals, err := readForeignHookRemovalsOnce(path)
		if err == nil || attempt == foreignHookRemovalsBusyRetries || !foreignHookRemovalsReadBusy(err) {
			return removals, err
		}
		time.Sleep(foreignHookRemovalsBusyDelay)
	}
}

func readForeignHookRemovalsOnce(path string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	if err := validateManagedGuardianAuthorization(path, "hook guardian foreign-hook removals"); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, enterprisepolicy.ForeignHookRemovalsMaxBytes+1))
	if err != nil {
		return nil, err
	}
	return enterprisepolicy.ParseForeignHookRemovals(data)
}
