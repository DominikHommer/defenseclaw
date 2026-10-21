// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The Windows standalone hook refuses, by itself, a call from an account the
// administrator excludes or has not enrolled yet, and reports the refusal on
// the gateway's refusal pipe (refusalpipe). The gateway writes the audit row
// an administrator reviews to see a leaver still trying to run agents
// (GAP-1242): a hook decision naming the account, the connector, the event
// and the tool, with action block and the refusal reason.
//
// The account is not trusted, so its reports are coalesced: the first
// refusal of an account and connector in a window is written at once, and
// the refusals that follow in the same window become one row with their
// count when the window ends. Each account holds at most one entry per
// connector and reason, and the table is bounded, so a refusal loop writes
// at most two rows a window per account and connector.
const (
	unenrolledRefusalWindow     = time.Minute
	unenrolledRefusalMaxEntries = 512
	unenrolledRefusalSubject    = "named_pipe_client"
	// unenrolledRefusalDrainTimeout bounds how long a stopping API server
	// waits for the last refusal rows: naming a domain account can wait on a
	// domain controller.
	unenrolledRefusalDrainTimeout = 5 * time.Second
)

type unenrolledRefusalKey struct {
	sid, connector, reason string
}

type unenrolledRefusalEntry struct {
	start   time.Time
	pending int
	last    refusalpipe.Report
}

// unenrolledRefusalRow is one row to write: attempts refusals of sid.
type unenrolledRefusalRow struct {
	SID      string
	Report   refusalpipe.Report
	Attempts int
}

type unenrolledRefusalAuditor struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[unenrolledRefusalKey]*unenrolledRefusalEntry
	write   func(unenrolledRefusalRow)
}

func newUnenrolledRefusalAuditor(write func(unenrolledRefusalRow)) *unenrolledRefusalAuditor {
	return &unenrolledRefusalAuditor{
		now:     time.Now,
		entries: make(map[unenrolledRefusalKey]*unenrolledRefusalEntry),
		write:   write,
	}
}

// record takes one verified report.
func (u *unenrolledRefusalAuditor) record(sid string, report refusalpipe.Report) {
	now := u.now()
	key := unenrolledRefusalKey{sid: sid, connector: report.Connector, reason: report.Reason}
	var rows []unenrolledRefusalRow
	u.mu.Lock()
	entry := u.entries[key]
	if entry != nil && now.Sub(entry.start) < unenrolledRefusalWindow {
		entry.pending++
		entry.last = report
		u.mu.Unlock()
		return
	}
	if entry != nil && entry.pending > 0 {
		rows = append(rows, unenrolledRefusalRow{SID: sid, Report: entry.last, Attempts: entry.pending})
	}
	if entry == nil && len(u.entries) >= unenrolledRefusalMaxEntries {
		rows = append(rows, u.expireLocked(now, false)...)
		if len(u.entries) >= unenrolledRefusalMaxEntries {
			u.mu.Unlock()
			u.writeAll(rows)
			return
		}
	}
	u.entries[key] = &unenrolledRefusalEntry{start: now, last: report}
	rows = append(rows, unenrolledRefusalRow{SID: sid, Report: report, Attempts: 1})
	u.mu.Unlock()
	u.writeAll(rows)
}

// flush writes the counts of the windows that have ended.
func (u *unenrolledRefusalAuditor) flush() {
	u.mu.Lock()
	rows := u.expireLocked(u.now(), false)
	u.mu.Unlock()
	u.writeAll(rows)
}

// drain writes the counts of every window, ended or not. A stop calls it so
// the refusals coalesced into an open window are not lost (GAP-1253).
func (u *unenrolledRefusalAuditor) drain() {
	u.mu.Lock()
	rows := u.expireLocked(u.now(), true)
	u.mu.Unlock()
	u.writeAll(rows)
}

func (u *unenrolledRefusalAuditor) expireLocked(now time.Time, all bool) []unenrolledRefusalRow {
	var rows []unenrolledRefusalRow
	for key, entry := range u.entries {
		if !all && now.Sub(entry.start) < unenrolledRefusalWindow {
			continue
		}
		if entry.pending > 0 {
			rows = append(rows, unenrolledRefusalRow{SID: key.sid, Report: entry.last, Attempts: entry.pending})
		}
		delete(u.entries, key)
	}
	return rows
}

func (u *unenrolledRefusalAuditor) writeAll(rows []unenrolledRefusalRow) {
	for _, row := range rows {
		u.write(row)
	}
}

// run flushes ended windows until ctx ends.
func (u *unenrolledRefusalAuditor) run(ctx context.Context) {
	ticker := time.NewTicker(unenrolledRefusalWindow / 4)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			u.flush()
			return
		case <-ticker.C:
			u.flush()
		}
	}
}

// runUnenrolledRefusalAudit serves refusal reports until ctx ends and then,
// before it returns, writes what a stop would otherwise lose: the rows still
// queued and the counts of the windows still open (GAP-1253). serve returns
// once ctx ends. Rows are written off the serving goroutines, since naming a
// domain account can wait on a domain controller, and with a context that a
// stop does not cancel, so the last rows still reach the audit log.
func runUnenrolledRefusalAudit(
	ctx context.Context,
	serve func(context.Context, *unenrolledRefusalAuditor),
	write func(context.Context, unenrolledRefusalRow),
) {
	rows := make(chan unenrolledRefusalRow, unenrolledRefusalMaxEntries)
	var queueMu sync.Mutex
	closed := false
	writeCtx := context.WithoutCancel(ctx)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for row := range rows {
			write(writeCtx, row)
		}
	}()
	auditor := newUnenrolledRefusalAuditor(func(row unenrolledRefusalRow) {
		queueMu.Lock()
		defer queueMu.Unlock()
		if closed {
			return // a report that arrived after the stop was drained
		}
		select {
		case rows <- row:
		default:
		}
	})
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		auditor.run(ctx)
	}()
	serve(ctx, auditor)
	<-runDone
	auditor.drain()
	queueMu.Lock()
	closed = true
	close(rows)
	queueMu.Unlock()
	<-writerDone
}

// auditUnenrolledRefusal writes one refusal row for an account the pipe
// client token identified.
func (a *APIServer) auditUnenrolledRefusal(ctx context.Context, row unenrolledRefusalRow) {
	if a == nil || ctx == nil {
		return
	}
	defer func() { _ = recover() }()
	sid := row.SID
	name := sanitizeLLMEventUser(userScopedIdentityName(sid))
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, sid)
	identity := AgentIdentityFromContext(ctx)
	identity.UserID, identity.UserIDKind, identity.UserName = sid, useridentity.KindForID(sid), verifiedAccountName(sid, name)
	ctx = ContextWithAgentIdentity(ctx, identity)
	ctx = attachVerifiedSubject(ctx, a.observabilityV8RuntimeEmitter(), sid, name, unenrolledRefusalSubject)
	extra := map[string]string{
		"refusal":  "unenrolled_account",
		"attempts": strconv.Itoa(row.Attempts),
	}
	if row.Report.Tool != "" {
		extra["tool"] = row.Report.Tool
	}
	event := row.Report.Event
	if event == "" {
		event = "unenrolled_refusal"
	}
	env := HookAuditEnvelope{
		Connector:  row.Report.Connector,
		Event:      event,
		Result:     "ok",
		Action:     "block",
		RawAction:  "block",
		Severity:   "MEDIUM",
		Mode:       "action",
		Reason:     row.Report.Reason,
		WouldBlock: true,
		Enforced:   true,
		Extra:      extra,
	}
	a.emitHookDecisionObservabilityV8(ctx, agentHookRequest{
		ConnectorName: row.Report.Connector,
		HookEventName: event,
		ToolName:      row.Report.Tool,
	}, agentHookResponse{
		Action: env.Action, RawAction: env.RawAction, Severity: env.Severity,
		Mode: env.Mode, Reason: env.Reason,
	}, env, false)
	if a.logger != nil {
		_ = a.logConnectorHookAuditEnvelope(ctx, env)
	}
}
