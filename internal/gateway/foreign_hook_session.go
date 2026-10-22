// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
	places := a.foreignHookSessionPlaces(dataDir)
	// The record folder's generation first, then the guardian's removals
	// (GAP-0352): the guardian bumps the generation after it recorded a
	// removal, so an answer stamped with a generation it has bumped since
	// proves nothing during an outage, and an answer stamped with the
	// current one was decided from removals at least as new as that bump.
	generation := places.generation()
	removals, removalsErr := a.readForeignHookRemovals(places, identity, generation)
	// Each identity has its own store, so only that identity's exchanges
	// are serialized; another account's exchange never waits on this one.
	unlock := a.foreignHookSessionLocks.lock(stateDir)
	decision := enterprisepolicy.ApplyForeignHookSession(enterprisepolicy.SessionUpdate{
		StateDir:     stateDir,
		Key:          exchange.Key,
		SessionStart: exchange.SessionStart,
		Decision:     exchange.Decision,
		Removals:     removals,
		RemovalsErr:  removalsErr,
		Now:          time.Now(),
		// A block is recorded in the private store only after the
		// protected records it overrules are out of use: the block is
		// published only after that write, and a gateway that stops in
		// between must not leave an allow the hook honors during the
		// outage (GAP-0352, 1.0.4 guard loop round 2).
		BeforeBlock: func() { withdrawForeignHookSessionDecision(places.recordRoot, identity, exchange.Key) },
	})
	// Under the same lock, so the protected record follows the store's
	// order: the hook reads it when the gateway is down.
	publishForeignHookSessionDecision(places.recordRoot, identity, exchange.Key, decision, generation)
	decision = a.recheckForeignHookSessionAllow(places, identity, exchange.Key, decision, generation)
	unlock()
	if decision.Deny {
		a.auditForeignHookSessionDenial(r.Context(), connector, exchange, decision)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

// recheckForeignHookSessionAllow reads the record generation and the
// guardian's removals again after an exchange decided and published an
// allow, right before it answers (GAP-0352, 1.0.4 review loop round 4): a
// removal the guardian recorded (its ledger, or the account's pending mark)
// while the exchange decided from the removals it read first must deny this
// call, not only the next one. A removal that now denies the call, or
// removals that can no longer be read, replace the allow with that denial,
// which is published with the generation read for it. An allow the new
// removals still allow is published again when the generation moved, so
// the hook keeps a current answer during an outage: it was checked against
// removals read after that generation. A denial is final and is returned
// as it is.
func (a *APIServer) recheckForeignHookSessionAllow(places foreignHookSessionPlaces, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, generation string) enterprisepolicy.GuardDecision {
	if decision.Deny {
		return decision
	}
	current := places.generation()
	removals, removalsErr := a.readForeignHookRemovals(places, identity, current)
	rechecked := enterprisepolicy.ApplyForeignHookRemovals(decision, key, removals, removalsErr, time.Now())
	if rechecked.Deny || current != generation {
		publishForeignHookSessionDecision(places.recordRoot, identity, key, rechecked, current)
	}
	return rechecked
}

// foreignHookSessionPublishRoot is the folder of the protected session
// records on a standalone host (managed.StandaloneLayout.HookSessionDir),
// foreignHookSessionRootForDataDir the same folder named by the gateway's
// data directory (managed.StandaloneHookSessionDirForDataDir),
// foreignHookSessionGeneration reads its generation
// (enterprisepolicy.PublishedSessionGeneration),
// foreignHookSessionPublish writes the protected record,
// foreignHookSessionWithdraw takes it out of use and
// foreignHookSessionCloseGeneration removes the generation file when that
// fails (replaceable in tests, whose folders cannot carry the per-account
// access list or a root-owned generation file).
var (
	foreignHookSessionPublishRoot    = standaloneHookSessionDir
	foreignHookSessionRootForDataDir = func(dataDir string) (string, bool) {
		return managed.StandaloneHookSessionDirForDataDir(runtime.GOOS, dataDir)
	}
	foreignHookSessionGeneration      = enterprisepolicy.PublishedSessionGeneration
	foreignHookSessionPublish         = enterprisepolicy.PublishForeignHookSessionDecision
	foreignHookSessionWithdraw        = enterprisepolicy.WithdrawPublishedForeignHookSession
	foreignHookSessionCloseGeneration = enterprisepolicy.ClosePublishedSessionGeneration
)

// foreignHookSessionPlaces are where one exchange reads the guardian's
// removals and writes its protected session record: the guardian's ledger
// folder (managed.HookGuardianAuthorizationDir), the gateway's data
// directory, which holds each account's private session store and so its
// pending mark (enterprisepolicy.ForeignHookRemovalPending), and the
// protected session record root ("" where this gateway publishes none).
// rootErr is a record root a standalone gateway could not locate at all
// (foreignHookSessionRecordRoot): the exchange is denied, because the
// gateway can then not publish its answer (GAP-0352 review).
type foreignHookSessionPlaces struct {
	removalsDir string
	dataDir     string
	recordRoot  string
	rootErr     error
}

func (a *APIServer) foreignHookSessionPlaces(dataDir string) foreignHookSessionPlaces {
	places := foreignHookSessionPlaces{removalsDir: managed.HookGuardianAuthorizationDir(dataDir), dataDir: dataDir}
	root, err := a.foreignHookSessionRecordRoot(dataDir)
	if err != nil {
		places.rootErr = fmt.Errorf("the protected foreign-hook session record folder cannot be located: %w", err)
	} else {
		places.recordRoot = strings.TrimSpace(root)
	}
	return places
}

// generation is the record folder's current generation, or "" where there
// is no record folder or its generation file cannot be read: an allow
// published without a generation proves nothing during an outage.
func (p foreignHookSessionPlaces) generation() string {
	if p.recordRoot == "" {
		return ""
	}
	generation, err := foreignHookSessionGeneration(p.recordRoot)
	if err != nil {
		return ""
	}
	return generation
}

// readForeignHookRemovals reads the guardian's removals for identity: those
// of the ledger, and an error that denies the call (a ledger that cannot be
// read, a record root that cannot be located, or the account's pending
// mark, enterprisepolicy.ErrForeignHookRemovalPending). The mark lives in
// the account's private session store, out of every standard user's reach.
// generation is the record generation the exchange read first: the ledger
// is read again whenever it changed (foreignHookRemovalCache.forIdentity).
func (a *APIServer) readForeignHookRemovals(places foreignHookSessionPlaces, identity, generation string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	removals, ledgerErr := a.foreignHookRemovals.forIdentity(places.removalsDir, identity, generation)
	pending, pendingErr := enterprisepolicy.ForeignHookRemovalPending(places.dataDir, identity)
	err := errors.Join(ledgerErr, pendingErr, places.rootErr)
	if pending {
		err = errors.Join(err, enterprisepolicy.ErrForeignHookRemovalPending)
	}
	return removals, err
}

// foreignHookSessionRecordRoot is the protected session record folder of a
// standalone gateway, or "" for Secure Client and per-user gateways, which
// have none. A lookup of the layout that fails (on Windows, the protected
// ProgramData registration cannot be read for a moment) falls back to the
// folder this gateway located last, and else to the one its data directory
// names (dataDir), so that an exchange still takes the records a block
// overrules out of use where the hook reads them (GAP-0352, 1.0.4 guard
// loop round 3). Only when none names a folder is it an error.
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
// exchange, stamped with generation, into the caller's protected session
// record under root, which the hook reads during a gateway outage under
// fail mode open (GAP-0352). A failure is logged and leaves no allow behind,
// so the hook blocks during an outage. Without a root nothing is published.
func publishForeignHookSessionDecision(root, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, generation string) {
	if root == "" {
		return
	}
	if err := foreignHookSessionPublish(root, identity, key, decision, generation, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record for %s was not written (the hook blocks during a gateway outage): %v\n",
			clipForeignHookAuditField(key.Connector, 64), err)
		if decision.Deny {
			// The publication revoked the record it could not replace; when
			// that failed too, the earlier allow must still not count.
			withdrawForeignHookSessionDecision(root, identity, key)
		}
	}
}

// withdrawForeignHookSessionDecision takes the caller's protected session
// records under root out of use before the exchange records a block, and
// after a block that could not be published
// (enterprisepolicy.WithdrawPublishedForeignHookSession). A withdrawal that
// fails does not count as one: the gateway then removes the record
// folder's generation file (enterprisepolicy.ClosePublishedSessionGeneration),
// which ends every allow there, of every account, until the next lifecycle
// run or guardian pass starts a new generation (GAP-0352, 1.0.4 guard loop
// round 3). When that fails too (a read-only volume, which the hook
// refuses as well, or Windows, where the gateway may not remove the file),
// it is logged. The block is recorded either way.
func withdrawForeignHookSessionDecision(root, identity string, key enterprisepolicy.SessionKey) {
	if root == "" {
		return
	}
	err := foreignHookSessionWithdraw(root, identity, key)
	if err == nil {
		return
	}
	connectorName := clipForeignHookAuditField(key.Connector, 64)
	if closeErr := foreignHookSessionCloseGeneration(root); closeErr != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record for %s could not be withdrawn before a block (%v), and the record generation could not be closed either: %v\n",
			connectorName, err, closeErr)
		return
	}
	fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record for %s could not be withdrawn before a block (%v), so the record generation was closed: guarded calls of every account block during a gateway outage until the next DefenseClaw repair or hook guardian removal\n",
		connectorName, err)
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
	mu         sync.Mutex
	path       string
	generation string
	info       os.FileInfo
	checkedAt  time.Time
	removals   []enterprisepolicy.ForeignHookRemoval
	err        error
}

const foreignHookRemovalRecheck = 2 * time.Second

// sameForeignHookRemovalsFile reports one ledger file, unchanged: the
// guardian replaces the ledger with a new file, so its identity changes
// even when its time and size do not.
func sameForeignHookRemovalsFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// forIdentity returns the removals the guardian recorded for one caller
// identity. A missing ledger records none; one that fails its trust check
// or does not parse is an error, which denies the call. The ledger is read
// again when the record generation changed since the cached read: the
// guardian bumps it after every ledger write, so an exchange that read the
// new generation never gets the ledger from before it (GAP-0352).
func (c *foreignHookRemovalCache) forIdentity(dir, identity, generation string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		c.path, c.info, c.removals, c.err = "", nil, nil, nil
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	// A failed read is not cached: the guardian sets the file's group only
	// after it replaces the file, and a read in between must not deny every
	// account's calls until the next recheck.
	if c.err != nil || path != c.path || generation != c.generation || !sameForeignHookRemovalsFile(c.info, info) ||
		now.Sub(c.checkedAt) >= foreignHookRemovalRecheck {
		// SameFile reads the Windows file ID on first use, by path: read it
		// now, while the path still names the file the cache describes.
		_ = os.SameFile(info, info)
		c.path, c.generation, c.info, c.checkedAt = path, generation, info, now
		c.removals, c.err = readForeignHookRemovals(path)
	}
	if c.err != nil {
		return nil, c.err
	}
	var out []enterprisepolicy.ForeignHookRemoval
	for _, removal := range c.removals {
		if canonical, ok := connector.CanonicalUserScopedIdentity(removal.Identity); ok && canonical == identity {
			out = append(out, removal)
		}
	}
	return out, nil
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
