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
	// The record key first, then the guardian's removals (GAP-0352): the
	// guardian removes the key before it records a removal and creates a new
	// one only after, so an allow made with a key read before a removal
	// proves nothing during an outage, and one made with the current key was
	// decided from removals at least as new as that key.
	recordKey := places.key()
	removals, removalsErr := a.readForeignHookRemovals(places, identity, recordKey.ID())
	// Each identity has its own store, so only that identity's exchanges
	// are serialized; another account's exchange never waits on this one.
	unlock := a.foreignHookSessionLocks.lock(stateDir)
	killed := false
	decision := enterprisepolicy.ApplyForeignHookSession(enterprisepolicy.SessionUpdate{
		StateDir:     stateDir,
		Key:          exchange.Key,
		SessionStart: exchange.SessionStart,
		Decision:     exchange.Decision,
		Removals:     removals,
		RemovalsErr:  removalsErr,
		Now:          time.Now(),
		// A block is recorded in the private store only after the key is
		// gone: the block is published only after that write, and a
		// gateway that stops in between, or whose publication fails, must
		// not leave an allow the hook honors during the outage (the kill
		// switch, GAP-0352 1.0.4 guard loop).
		BeforeBlock: func() { killed = a.killForeignHookSessionKey(places, identity, exchange.Key, false) },
	})
	if decision.Deny && !killed {
		// Every denial is published only after the key is gone.
		a.killForeignHookSessionKey(places, identity, exchange.Key, true)
	}
	// Under the same lock, so the protected record follows the store's
	// order: the hook reads it when the gateway is down.
	a.publishForeignHookSessionDecision(places.recordRoot, identity, exchange.Key, decision, recordKey)
	decision = a.recheckForeignHookSessionAllow(places, identity, exchange.Key, decision, recordKey)
	unlock()
	if decision.Deny {
		a.auditForeignHookSessionDenial(r.Context(), connector, exchange, decision)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

// recheckForeignHookSessionAllow reads the record key and the guardian's
// removals again after an exchange decided and published an allow, right
// before it answers (GAP-0352, 1.0.4 review loop round 4): a removal the
// guardian recorded (its ledger, or the account's pending mark) while the
// exchange decided from the removals it read first must deny this call,
// not only the next one. A removal that now denies the call, or removals
// that can no longer be read, replace the allow with that denial: the key
// is removed first, and the denial is published. An allow the new removals
// still allow is published again under the key read for them when the key
// changed, so the hook keeps a current answer during an outage. A denial
// is final and is returned as it is.
func (a *APIServer) recheckForeignHookSessionAllow(places foreignHookSessionPlaces, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey) enterprisepolicy.GuardDecision {
	if decision.Deny {
		return decision
	}
	current := places.key()
	removals, removalsErr := a.readForeignHookRemovals(places, identity, current.ID())
	rechecked := enterprisepolicy.ApplyForeignHookRemovals(decision, key, removals, removalsErr, time.Now())
	switch {
	case rechecked.Deny:
		a.killForeignHookSessionKey(places, identity, key, false)
		a.publishForeignHookSessionDecision(places.recordRoot, identity, key, rechecked, enterprisepolicy.SessionRecordKey{})
	case current.ID() != recordKey.ID():
		a.publishForeignHookSessionDecision(places.recordRoot, identity, key, rechecked, current)
	}
	return rechecked
}

// foreignHookSessionPublishRoot is the folder of the protected session
// records on a standalone host (managed.StandaloneLayout.HookSessionDir),
// foreignHookSessionRootForDataDir the same folder named by the gateway's
// data directory (managed.StandaloneHookSessionDirForDataDir),
// foreignHookSessionKey reads its key
// (enterprisepolicy.ReadPublishedSessionKey), foreignHookSessionPublish
// writes the protected record and foreignHookSessionKill removes the key
// (replaceable in tests).
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
// folder (managed.HookGuardianAuthorizationDir), the gateway's data
// directory, which holds each account's private session store and so its
// pending mark (enterprisepolicy.ForeignHookRemovalPending), and the
// protected session record root ("" where this gateway publishes none).
// rootErr is a record root a standalone gateway could not locate at all
// (foreignHookSessionRecordRoot): the exchange is denied, because the
// gateway can then neither remove the key nor publish its answer (GAP-0352
// review).
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

// key is the record folder's current key, or none where there is no record
// folder or its key cannot be read: an allow published without a key
// proves nothing during an outage.
func (p foreignHookSessionPlaces) key() enterprisepolicy.SessionRecordKey {
	if p.recordRoot == "" {
		return enterprisepolicy.SessionRecordKey{}
	}
	key, err := foreignHookSessionKey(p.recordRoot)
	if err != nil {
		return enterprisepolicy.SessionRecordKey{}
	}
	return key
}

// readForeignHookRemovals reads the guardian's removals for identity: those
// of the ledger, and an error that denies the call (a ledger that cannot be
// read, a record root that cannot be located, or the account's pending
// mark, enterprisepolicy.ErrForeignHookRemovalPending). The mark lives in
// the account's private session store, out of every standard user's reach.
// keyID names the record key the exchange read first: the ledger is read
// again whenever it changed (foreignHookRemovalCache.forIdentity).
func (a *APIServer) readForeignHookRemovals(places foreignHookSessionPlaces, identity, keyID string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	removals, ledgerErr := a.foreignHookRemovals.forIdentity(places.removalsDir, identity, keyID)
	pending, pendingErr := enterprisepolicy.ForeignHookRemovalPending(places.dataDir, identity)
	err := errors.Join(ledgerErr, pendingErr, places.rootErr)
	if pending {
		err = errors.Join(err, enterprisepolicy.ErrForeignHookRemovalPending)
	}
	return removals, err
}

// foreignHookSessionRecordRoot is the protected session record folder of a
// standalone gateway, or "" for Secure Client and per-user gateways, which
// have none. On Linux and macOS the layout is fixed. A lookup of the
// Windows layout that fails (the protected ProgramData registration cannot
// be read for a moment) falls back to the folder this gateway located last,
// and else to the one its data directory names (dataDir), so that an
// exchange still removes the key where the hook reads it (GAP-0352, 1.0.4
// guard loop round 3). Only when none names a folder is it an error.
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
// is logged; the key was removed before every denial, so a record the
// gateway could not replace proves nothing. Publishing an allow ends what
// the key removal cache knows about the key (foreignHookSessionKillCache).
// Without a root nothing is published.
func (a *APIServer) publishForeignHookSessionDecision(root, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey) {
	if root == "" {
		return
	}
	if decision.Deny {
		recordKey = enterprisepolicy.SessionRecordKey{}
	} else {
		a.foreignHookSessionKilled.forget(identity, key)
	}
	if err := foreignHookSessionPublish(root, identity, key, decision, recordKey, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record for %s was not written (the hook blocks during a gateway outage): %v\n",
			clipForeignHookAuditField(key.Connector, 64), err)
	}
}

// killForeignHookSessionKey removes the record folder's key before the
// exchange records a block, and before it publishes any denial (the kill
// switch, GAP-0352 1.0.4 guard loop): every allow written before proves
// nothing during an outage from then on, of every account, until the hook
// guardian creates a new key (it does at every pass). reuse lets a denial
// skip the removal when this gateway already removed the key for it and
// published no allow for its process or session since
// (foreignHookSessionKillCache): a blocked agent that keeps calling then
// does not end every other account's outage allows at each call. A removal
// that fails is logged; the block is still recorded and published, and the
// published block denies during an outage. It reports whether the key is
// gone for this denial.
func (a *APIServer) killForeignHookSessionKey(places foreignHookSessionPlaces, identity string, key enterprisepolicy.SessionKey, reuse bool) bool {
	connectorName := clipForeignHookAuditField(key.Connector, 64)
	if places.recordRoot == "" {
		if places.rootErr != nil {
			fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record key for %s could not be removed before a block: %v\n", connectorName, places.rootErr)
		}
		return false
	}
	if reuse && a.foreignHookSessionKilled.covers(identity, key) {
		return true
	}
	if err := foreignHookSessionKill(places.recordRoot); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the protected session record key for %s could not be removed before a block, so only the published block denies during a gateway outage: %v\n",
			connectorName, err)
		return false
	}
	a.foreignHookSessionKilled.add(identity, key)
	return true
}

// foreignHookSessionKillCache names the agent processes and sessions, per
// account and connector, whose denial this gateway already removed the key
// for and that it published no allow for since. Only those may skip the
// removal (killForeignHookSessionKey): the key they could have been allowed
// under is gone, and no allow under a later key was published for them, so
// no allow of theirs proves anything. It forgets everything past
// foreignHookSessionKillCacheLimit entries and on a restart, which only
// makes a later denial remove the key again.
type foreignHookSessionKillCache struct {
	mu      sync.Mutex
	entries map[string]struct{}
}

const foreignHookSessionKillCacheLimit = 4096

func foreignHookSessionKillNames(identity string, key enterprisepolicy.SessionKey) []string {
	var names []string
	for _, entry := range []struct{ kind, id string }{{"p", key.Process}, {"s", key.Session}} {
		if entry.id != "" {
			names = append(names, identity+"\x00"+key.Connector+"\x00"+entry.kind+"\x00"+entry.id)
		}
	}
	return names
}

// covers reports a denial of key whose process and session (each it names)
// are both known.
func (c *foreignHookSessionKillCache) covers(identity string, key enterprisepolicy.SessionKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := foreignHookSessionKillNames(identity, key)
	for _, name := range names {
		if _, ok := c.entries[name]; !ok {
			return false
		}
	}
	return len(names) != 0
}

func (c *foreignHookSessionKillCache) add(identity string, key enterprisepolicy.SessionKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := foreignHookSessionKillNames(identity, key)
	if c.entries == nil || len(c.entries)+len(names) > foreignHookSessionKillCacheLimit {
		c.entries = map[string]struct{}{}
	}
	for _, name := range names {
		c.entries[name] = struct{}{}
	}
}

func (c *foreignHookSessionKillCache) forget(identity string, key enterprisepolicy.SessionKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, name := range foreignHookSessionKillNames(identity, key) {
		delete(c.entries, name)
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
