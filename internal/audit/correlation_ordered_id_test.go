// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestOrderedCorrelationIDs(t *testing.T) {
	first, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	second, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	a := orderedCorrelationID("rel_", string(first), "semantic_event", string(first), "session", "s")
	if a != orderedCorrelationID("rel_", string(first), "semantic_event", string(first), "session", "s") {
		t.Fatal("the same fields got two IDs")
	}
	if a == orderedCorrelationID("rel_", string(first), "semantic_event", string(first), "session", "t") {
		t.Fatal("different fields got the same ID")
	}
	parsed := uuid.MustParse(string(first))
	if len(a) != 68 || !strings.HasPrefix(a, "rel_"+hex.EncodeToString(parsed[:8])) {
		t.Fatalf("ordered ID %q does not start with the anchor's time and counter", a)
	}
	b := orderedCorrelationID("rel_", string(second), "semantic_event", string(second), "session", "s")
	if !(a < b) {
		t.Fatalf("a later event's ID %q sorts before %q", b, a)
	}
	for _, anchor := range []string{"", "not-a-uuid", uuid.NewString(), strings.ToUpper(string(first))} {
		got := orderedCorrelationID("ev_", anchor, "x", anchor)
		if got != deterministicCorrelationID("ev_", "x", anchor) {
			t.Fatalf("anchor %q: got %q, want the unordered ID", anchor, got)
		}
	}
	if id := observability.NewTimeOrderedID(); uuid.MustParse(id).Version() != 7 || uuid.MustParse(id).String() != id {
		t.Fatalf("NewTimeOrderedID = %q, want a canonical UUIDv7", id)
	}
	previous := ""
	for range 1000 {
		id, err := observability.TimeOrderedOccurrenceIDs.NewOccurrenceID()
		if err != nil {
			t.Fatal(err)
		}
		if id <= previous {
			t.Fatalf("occurrence ID %q is not after %q", id, previous)
		}
		previous = id
	}
}

// TestCorrelationUpsertsKeepUnorderedIDsOfOlderStores pins the upgrade path:
// an identifier, relationship or evidence row written before 1.0.4 has the
// unordered deterministicCorrelationID of its fields. Writing the same fields
// again must update that row, not add a second one or fail on the table's
// unique fields, and must return the stored ID.
func TestCorrelationUpsertsKeepUnorderedIDsOfOlderStores(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	logical, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	createTx, result, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: LogicalEventID(logical),
		Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: CorrelationRailHook, EventName: "tool.started", ReceivedTime: now,
		ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
	}})
	if err != nil || result.Status != CorrelationOccurrenceNew {
		t.Fatalf("create result=%+v err=%v", result, err)
	}
	identifier := CorrelationIdentifier{
		SemanticEventID: semantic, ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex.hook",
		Kind: CorrelationIdentifierTool, ValueDigest: correlationDigest("toolu_1"),
		NormalizedValue: "toolu_1", SourceField: "tool_use_id", Origin: CorrelationOriginReported,
		ProfileVersion: instance.ProfileVersion, ObservedAt: now,
	}
	relationship := CorrelationRelationshipInput{
		FromKind: CorrelationNodeSemanticEvent, FromID: string(semantic),
		ToKind: CorrelationNodeTool, ToID: "toolu_1",
		Type: CorrelationBelongsTo, Method: CorrelationMethodReported,
		RuleID: "hook-tool", RuleVersion: "v1", Status: CorrelationRelationshipActive, ObservedAt: now,
	}
	identifierID, err := createTx.PutIdentifier(t.Context(), identifier)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := createTx.PutRelationship(t.Context(), relationship)
	if err != nil {
		t.Fatal(err)
	}
	anchor := uuid.MustParse(string(semantic))
	prefix := hex.EncodeToString(anchor[:8])
	if !strings.HasPrefix(identifierID, "id_"+prefix) || !strings.HasPrefix(stored.RelationshipID, "rel_"+prefix) {
		t.Fatalf("new rows are not time ordered: %s %s", identifierID, stored.RelationshipID)
	}
	if err := createTx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Rewrite the identifier and relationship as an older binary stored them.
	legacyIdentifier := deterministicCorrelationID("id_", string(identifier.ConnectorInstanceID),
		identifier.Namespace, string(identifier.Kind), identifier.ValueDigest, string(identifier.SemanticEventID))
	legacyRelationship := deterministicCorrelationID("rel_", string(relationship.FromKind), relationship.FromID,
		string(relationship.ToKind), relationship.ToID, string(relationship.Type), string(relationship.Method),
		relationship.RuleID, relationship.RuleVersion)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`UPDATE correlation_identifiers SET identifier_id=? WHERE identifier_id=?`, []any{legacyIdentifier, identifierID}},
		{`UPDATE correlation_relationships SET relationship_id=? WHERE relationship_id=?`, []any{legacyRelationship, stored.RelationshipID}},
	} {
		if _, err := store.db.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	evidence := CorrelationRelationshipEvidence{
		RelationshipID: legacyRelationship, SemanticEventID: semantic,
		Role: CorrelationEvidenceSource, Integrity: CorrelationIntegrityVerified, CreatedAt: now,
	}
	attach := func() (string, CorrelationRelationship, string) {
		t.Helper()
		tx, _, err := repo.BeginExistingOccurrence(t.Context(), semantic)
		if err != nil {
			t.Fatal(err)
		}
		gotIdentifier, err := tx.PutIdentifier(t.Context(), identifier)
		if err != nil {
			t.Fatal(err)
		}
		gotRelationship, err := tx.PutRelationship(t.Context(), relationship)
		if err != nil {
			t.Fatal(err)
		}
		gotEvidence, err := tx.PutRelationshipEvidence(t.Context(), evidence)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return gotIdentifier, gotRelationship, gotEvidence
	}
	gotIdentifier, gotRelationship, evidenceID := attach()
	if gotIdentifier != legacyIdentifier || gotRelationship.RelationshipID != legacyRelationship || !gotRelationship.Unchanged {
		t.Fatalf("upserts over an older row returned %s %+v, want %s %s", gotIdentifier, gotRelationship,
			legacyIdentifier, legacyRelationship)
	}
	if !strings.HasPrefix(evidenceID, "ev_"+prefix) {
		t.Fatalf("new evidence %s is not time ordered", evidenceID)
	}
	legacyEvidence := deterministicCorrelationID("ev_", legacyRelationship, string(semantic), string(CorrelationEvidenceSource))
	if _, err := store.db.Exec(`UPDATE correlation_relationship_evidence SET evidence_id=? WHERE evidence_id=?`,
		legacyEvidence, evidenceID); err != nil {
		t.Fatal(err)
	}
	if _, _, again := attach(); again != legacyEvidence {
		t.Fatalf("evidence upsert over an older row returned %s, want %s", again, legacyEvidence)
	}
	for table, want := range map[string]int{
		"correlation_identifiers": 1, "correlation_relationships": 1, "correlation_relationship_evidence": 1,
	} {
		var count int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s has %d rows, want %d", table, count, want)
		}
	}
}

// TestCorrelationLookupsUseUniqueIndexesAfterTheTrim pins that the two
// correlation indexes trimUnreadAuditIndexes drops are not needed: their
// lookups use the unique index with the same leading columns.
func TestCorrelationLookupsUseUniqueIndexesAfterTheTrim(t *testing.T) {
	store, _ := newCorrelationTestStore(t)
	for _, name := range []string{"idx_correlation_identifiers_exact", "idx_correlation_receipts_source"} {
		var count int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("index %s kept", name)
		}
	}
	plan := func(query string, args ...any) string {
		t.Helper()
		rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+query, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var id, parent, unused int
			var detail sql.NullString
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, detail.String)
		}
		return strings.Join(lines, "; ")
	}
	for _, check := range []struct{ query, index string }{
		{`SELECT event.semantic_event_id FROM correlation_identifiers AS identifier
			JOIN correlation_events AS event ON event.semantic_event_id=identifier.semantic_event_id
			WHERE identifier.connector_instance_id='c' AND ((identifier.namespace='n' AND identifier.identifier_kind='session' AND identifier.value_digest='d')
			OR (identifier.namespace='n' AND identifier.identifier_kind='tool_invocation' AND identifier.value_digest='e')) LIMIT 1`,
			"sqlite_autoindex_correlation_identifiers_2"},
		{`SELECT semantic_event_id FROM correlation_receipts
			WHERE connector_instance_id='c' AND source_key_digest='d' AND fingerprint_sha256<>'f'
			ORDER BY first_received_time_unix_nano, semantic_event_id LIMIT 1`,
			"sqlite_autoindex_correlation_receipts_1"},
	} {
		got := plan(check.query)
		if !strings.Contains(got, check.index) {
			t.Fatalf("plan %q does not use %s", got, check.index)
		}
	}
}
