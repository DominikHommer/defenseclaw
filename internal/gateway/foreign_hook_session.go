// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
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
	stateDir := foreignHookSessionStateDir(dataDir, identity)
	removalsDir := managed.HookGuardianAuthorizationDir(dataDir)
	view := a.readForeignHookRemovals(removalsDir, identity)
	// Each identity has its own store, so only that identity's exchanges
	// are serialized; another account's exchange never waits on this one.
	unlock := a.foreignHookSessionLocks.lock(stateDir)
	decision := enterprisepolicy.ApplyForeignHookSession(enterprisepolicy.SessionUpdate{
		StateDir:     stateDir,
		Key:          exchange.Key,
		SessionStart: exchange.SessionStart,
		Decision:     exchange.Decision,
		Removals:     view.removals,
		RemovalsErr:  view.err,
		Now:          time.Now(),
	})
	// Under the same lock, so the protected record follows the store's
	// order: the hook reads it when the gateway is down (GAP-0352).
	decision = a.settleForeignHookSessionDecision(removalsDir, identity, exchange.Key, decision, view)
	unlock()
	if decision.Deny {
		a.auditForeignHookSessionDenial(r.Context(), connector, exchange, decision)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

// foreignHookSessionPublishRoot is the folder of the protected session
// records on a standalone host (managed.StandaloneLayout.HookSessionDir),
// replaceable in tests.
var foreignHookSessionPublishRoot = standaloneHookSessionDir

// foreignHookSessionPublish writes the protected record and
// foreignHookSessionWithdraw revokes it (replaceable in tests, whose
// folders cannot carry the per-account access list).
var (
	foreignHookSessionPublish  = enterprisepolicy.PublishForeignHookSessionDecision
	foreignHookSessionWithdraw = enterprisepolicy.WithdrawPublishedForeignHookSession
)

// foreignHookRemovalView is what one exchange read of the guardian's
// removals for its caller: the removals of the hold and the ledger, an error
// that denies the call (a file that cannot be read, or the account's
// pending mark, enterprisepolicy.ErrForeignHookRemovalPending), and the
// stamps of both files.
type foreignHookRemovalView struct {
	removals []enterprisepolicy.ForeignHookRemoval
	err      error
	ledger   foreignHookRemovalStamp
	hold     foreignHookRemovalStamp
}

// readForeignHookRemovals reads the view for identity. The hold comes first:
// the guardian deletes a hold only after its ledger holds the removals, so
// the exchange sees them in one or the other. The pending mark comes last:
// the guardian clears it only after its ledger or hold names the removal.
func (a *APIServer) readForeignHookRemovals(dir, identity string) foreignHookRemovalView {
	held, holdStamp, holdErr := a.foreignHookRemovalHold(identity)
	removals, ledgerStamp, ledgerErr := a.foreignHookRemovals.forIdentity(dir, identity)
	pending, pendingErr := a.foreignHookRemovalPending(identity)
	view := foreignHookRemovalView{
		removals: append(removals, held...),
		err:      errors.Join(ledgerErr, holdErr, pendingErr),
		ledger:   ledgerStamp,
		hold:     holdStamp,
	}
	if pending {
		view.err = errors.Join(view.err, enterprisepolicy.ErrForeignHookRemovalPending)
	}
	return view
}

// foreignHookRemovalsChanged reports whether the guardian changed what view
// read: it wrote, replaced or removed the ledger or the hold, or it marked
// the account pending.
func (a *APIServer) foreignHookRemovalsChanged(identity string, view foreignHookRemovalView) bool {
	if view.ledger.changed() || view.hold.changed() {
		return true
	}
	if errors.Is(view.err, enterprisepolicy.ErrForeignHookRemovalPending) {
		return false
	}
	pending, err := a.foreignHookRemovalPending(identity)
	return pending || err != nil
}

// foreignHookSessionSettleReads bounds how often one exchange reads the
// guardian's removals.
const foreignHookSessionSettleReads = 3

// errForeignHookRemovalsUnsettled denies an exchange whose removals kept
// changing.
var errForeignHookRemovalsUnsettled = errors.New("the guardian's foreign-hook removals kept changing during this exchange")

// settleForeignHookSessionDecision publishes the answer of one exchange
// (publishForeignHookSessionDecision) and returns the answer the hook gets.
// The answer used the guardian's removals as view read them before the
// per-identity lock, and the guardian writes its ledger (or the hold, or the
// pending mark) first and revokes the account's records after it. So an
// allow is checked after its publication: when the guardian changed what
// view read, the allow is withdrawn, the removals are read again and the
// answer is decided again from them, which may deny the call (GAP-0352
// review). Either this check sees the change, or the guardian's revocation
// comes after the publication and removes it, and the answer was given
// before the removal was recorded. A block is never withdrawn. After
// foreignHookSessionSettleReads reads that all changed, the call is denied.
func (a *APIServer) settleForeignHookSessionDecision(dir, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, view foreignHookRemovalView) enterprisepolicy.GuardDecision {
	for read := 1; ; read++ {
		a.publishForeignHookSessionDecision(identity, key, decision)
		if decision.Deny || !a.foreignHookRemovalsChanged(identity, view) {
			return decision
		}
		a.withdrawForeignHookSessionDecision(identity, key)
		if read == foreignHookSessionSettleReads {
			decision = enterprisepolicy.ApplyForeignHookRemovals(decision, key, nil, errForeignHookRemovalsUnsettled, time.Now())
			continue
		}
		view = a.readForeignHookRemovals(dir, identity)
		decision = enterprisepolicy.ApplyForeignHookRemovals(decision, key, view.removals, view.err, time.Now())
	}
}

// foreignHookSessionRecordRoot is the protected session record folder of a
// standalone gateway, or "" for Secure Client and per-user gateways, which
// have none.
func (a *APIServer) foreignHookSessionRecordRoot() (string, error) {
	cfg := a.scannerCfg
	if cfg == nil || !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() {
		return "", nil
	}
	return foreignHookSessionPublishRoot()
}

// publishForeignHookSessionDecision writes the answer of one session
// exchange into the caller's protected session record, which the hook reads
// during a gateway outage under fail mode open (GAP-0352). A failure is
// logged and leaves no allow behind, so the hook blocks during an outage.
func (a *APIServer) publishForeignHookSessionDecision(identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision) {
	root, err := a.foreignHookSessionRecordRoot()
	if err == nil && root == "" {
		return
	}
	if err == nil {
		err = foreignHookSessionPublish(root, identity, key, decision, time.Now())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record for %s was not written (the hook blocks during a gateway outage): %v\n",
			clipForeignHookAuditField(key.Connector, 64), err)
	}
}

// withdrawForeignHookSessionDecision revokes the answer it published for
// key; the record then reads as missing, which blocks during an outage.
func (a *APIServer) withdrawForeignHookSessionDecision(identity string, key enterprisepolicy.SessionKey) {
	root, err := a.foreignHookSessionRecordRoot()
	if err != nil || root == "" {
		return
	}
	if err := foreignHookSessionWithdraw(root, identity, key); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record for %s was not withdrawn: %v\n",
			clipForeignHookAuditField(key.Connector, 64), err)
	}
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

// foreignHookRemovalCache holds the guardian's foreign-hook removal ledger
// (enterprisepolicy.ForeignHookRemovalsFile), read again when the file
// changes and at least every foreignHookRemovalRecheck.
type foreignHookRemovalCache struct {
	mu        sync.Mutex
	path      string
	info      os.FileInfo
	checkedAt time.Time
	removals  []enterprisepolicy.ForeignHookRemoval
	err       error
}

const foreignHookRemovalRecheck = 2 * time.Second

// foreignHookRemovalStamp is the removal ledger, or hold, file at path an
// answer came from; info is nil when there was none. A stamp without a
// path (no hold on this host) never changes.
type foreignHookRemovalStamp struct {
	path string
	info os.FileInfo
}

// changed reports whether the file at the stamp's path is no longer the
// file the stamp names: the guardian wrote, replaced or removed it since. A
// file that cannot be inspected counts as changed.
func (s foreignHookRemovalStamp) changed() bool {
	if s.path == "" {
		return false
	}
	info, err := os.Lstat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s.info != nil
	}
	return err != nil || !sameForeignHookRemovalsFile(s.info, info)
}

// foreignHookRemovalHold reads the removals the guardian holds for identity
// next to its protected session records because it could not write them to
// its ledger (enterprisepolicy.ReadForeignHookRemovalHold): the exchange
// denies with them as with the ledger, so a revoked allow is not published
// again for an agent process that started before the removal. Only a
// standalone gateway has the record folder.
func (a *APIServer) foreignHookRemovalHold(identity string) ([]enterprisepolicy.ForeignHookRemoval, foreignHookRemovalStamp, error) {
	root, err := a.foreignHookSessionRecordRoot()
	if err != nil || strings.TrimSpace(root) == "" {
		return nil, foreignHookRemovalStamp{}, nil
	}
	path, ok := enterprisepolicy.ForeignHookRemovalHoldPath(root, identity)
	if !ok {
		return nil, foreignHookRemovalStamp{}, nil
	}
	removals, info, err := enterprisepolicy.ReadForeignHookRemovalHold(root, identity)
	return removals, foreignHookRemovalStamp{path: path, info: info}, err
}

// foreignHookRemovalPending reports the guardian's pending mark of identity
// (enterprisepolicy.ForeignHookRemovalPending): the guardian removed one of
// the account's hooks and could not record it, so every guarded call of the
// account is denied. Only a standalone gateway has the record folder.
func (a *APIServer) foreignHookRemovalPending(identity string) (bool, error) {
	root, err := a.foreignHookSessionRecordRoot()
	if err != nil || strings.TrimSpace(root) == "" {
		return false, nil
	}
	return enterprisepolicy.ForeignHookRemovalPending(root, identity)
}

// sameForeignHookRemovalsFile reports one ledger file, unchanged: the
// guardian replaces the ledger with a new file, so its identity changes
// even when its time and size do not.
func sameForeignHookRemovalsFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// forIdentity returns the removals the guardian recorded for one caller
// identity, with the stamp of the ledger file they came from. A missing
// ledger records none; one that fails its trust check or does not parse is
// an error, which denies the call.
func (c *foreignHookRemovalCache) forIdentity(dir, identity string) ([]enterprisepolicy.ForeignHookRemoval, foreignHookRemovalStamp, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		c.path, c.info, c.removals, c.err = "", nil, nil, nil
		return nil, foreignHookRemovalStamp{path: path}, nil
	}
	if err != nil {
		return nil, foreignHookRemovalStamp{}, err
	}
	now := time.Now()
	// A failed read is not cached: the guardian sets the file's group only
	// after it replaces the file, and a read in between must not deny every
	// account's calls until the next recheck.
	if c.err != nil || path != c.path || !sameForeignHookRemovalsFile(c.info, info) || now.Sub(c.checkedAt) >= foreignHookRemovalRecheck {
		// SameFile reads the Windows file ID on first use, by path: read it
		// now, while the path still names the file the stamp describes.
		_ = os.SameFile(info, info)
		c.path, c.info, c.checkedAt = path, info, now
		c.removals, c.err = readForeignHookRemovals(path)
	}
	if c.err != nil {
		return nil, foreignHookRemovalStamp{}, c.err
	}
	var out []enterprisepolicy.ForeignHookRemoval
	for _, removal := range c.removals {
		if canonical, ok := connector.CanonicalUserScopedIdentity(removal.Identity); ok && canonical == identity {
			out = append(out, removal)
		}
	}
	return out, foreignHookRemovalStamp{path: path, info: c.info}, nil
}

func readForeignHookRemovals(path string) ([]enterprisepolicy.ForeignHookRemoval, error) {
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

// foreignHookSessionStateDir is the session store of one caller identity.
func foreignHookSessionStateDir(dataDir, identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(dataDir, "foreign-hook-sessions", fmt.Sprintf("%x", digest[:20]))
}
