// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func storedMatchRecord(t *testing.T, change func(*observability.RecordInput)) observability.Record {
	t.Helper()
	input := observability.RecordInput{
		Timestamp: time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
		RecordID:  "stored-change",
		Identity: observability.EventIdentity{
			Bucket: observability.BucketDiagnostic, Signal: observability.SignalLogs, Name: "diagnostic.message",
		},
		Source: observability.SourceGateway, Action: "install", Outcome: observability.OutcomeApplied,
		Correlation: observability.Correlation{RunID: "run-before", SidecarInstanceID: "sidecar-before"},
		Provenance: observability.Provenance{
			Producer: "audit_logger", BinaryVersion: "1.0.4", RegistrySchemaVersion: 1,
			ConfigGeneration: 3, ConfigDigest: strings.Repeat("d", 64),
		},
		Body: map[string]any{
			"sha256":  strings.Repeat("a", 64),
			"keys":    []any{"bundle-key-2"},
			"account": "os:uid:0:root",
			"reason":  "trust anchors applied",
			"note":    "operator note",
		},
		FieldClasses: map[string]observability.FieldClass{
			"/sha256":  observability.FieldClassMetadata,
			"/keys/0":  observability.FieldClassMetadata,
			"/account": observability.FieldClassIdentifier,
			"/reason":  observability.FieldClassReason,
			"/note":    observability.FieldClassContent,
		},
	}
	if change != nil {
		change(&input)
	}
	record, err := observability.NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// A replay of a stored occurrence is sent only when it is the stored
// record. The check reads only the stored local projection: it holds every
// envelope member verbatim and the metadata and identifier values verbatim
// under every profile, so a replay under another outcome, time, id,
// provenance or body value is refused whichever profile stored it, and a
// reload or key rotation since cannot make the stored record mismatch.
// Before, a replay was compared on its schema, event, time and provenance
// only, so another outcome or body went out under the stored id.
func TestMatchStoredProjectionAcceptsOnlyTheStoredRecord(t *testing.T) {
	engine := newTestEngine(t)
	failed := observability.OutcomeFailed
	medium := observability.SeverityMedium
	variants := map[string]func(*observability.RecordInput){
		"another outcome":     func(in *observability.RecordInput) { in.Outcome = failed },
		"another severity":    func(in *observability.RecordInput) { in.Severity = &medium },
		"another action":      func(in *observability.RecordInput) { in.Action = "remove" },
		"another time":        func(in *observability.RecordInput) { in.Timestamp = in.Timestamp.Add(time.Second) },
		"another id":          func(in *observability.RecordInput) { in.RecordID = "another-change" },
		"another run":         func(in *observability.RecordInput) { in.Correlation.RunID = "run-after" },
		"another generation":  func(in *observability.RecordInput) { in.Provenance.ConfigGeneration = 4 },
		"another config":      func(in *observability.RecordInput) { in.Provenance.ConfigDigest = strings.Repeat("e", 64) },
		"another binary":      func(in *observability.RecordInput) { in.Provenance.BinaryVersion = "1.0.5" },
		"another anchor hash": func(in *observability.RecordInput) { in.Body.(map[string]any)["sha256"] = strings.Repeat("c", 64) },
		"another account":     func(in *observability.RecordInput) { in.Body.(map[string]any)["account"] = "os:uid:501:alice" },
		"another key":         func(in *observability.RecordInput) { in.Body.(map[string]any)["keys"] = []any{"bundle-key-3"} },
		"another field class": func(in *observability.RecordInput) { in.FieldClasses["/sha256"] = observability.FieldClassIdentifier },
		"one more body field": func(in *observability.RecordInput) {
			in.Body.(map[string]any)["code"] = "interrupted"
			in.FieldClasses["/code"] = observability.FieldClassMetadata
		},
	}
	for _, profile := range BuiltInProfiles() {
		stored := storedMatchRecord(t, nil)
		projection, _, err := engine.Project(stored, profile)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := projection.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if err := MatchStoredProjection(storedMatchRecord(t, nil), encoded); err != nil {
			t.Fatalf("%s: the stored record does not match its projection: %v", profile.Name(), err)
		}
		for name, change := range variants {
			if MatchStoredProjection(storedMatchRecord(t, change), encoded) == nil {
				t.Errorf("%s: a record with %s matched the stored record", profile.Name(), name)
			}
		}
	}

	// Without a redacting profile every body value is compared, so a field
	// the stored record lacks, or another reason or note, is refused too.
	none, _ := BuiltInProfile(ProfileNone)
	projection, _, err := engine.Project(storedMatchRecord(t, nil), none)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := projection.Bytes()
	for name, change := range map[string]func(*observability.RecordInput){
		"another reason": func(in *observability.RecordInput) { in.Body.(map[string]any)["reason"] = "trust anchors failed" },
		"another note":   func(in *observability.RecordInput) { in.Body.(map[string]any)["note"] = "another note" },
		"no note": func(in *observability.RecordInput) {
			delete(in.Body.(map[string]any), "note")
			delete(in.FieldClasses, "/note")
		},
	} {
		if MatchStoredProjection(storedMatchRecord(t, change), encoded) == nil {
			t.Errorf("a record with %s matched the stored record", name)
		}
	}
	for name, stored := range map[string]string{
		"no stored record":       "",
		"not JSON":               "{",
		"no projection metadata": strings.Replace(string(encoded), `"projection":`, `"projected":`, 1),
	} {
		if MatchStoredProjection(storedMatchRecord(t, nil), []byte(stored)) == nil {
			t.Errorf("a stored row with %s matched", name)
		}
	}
}
