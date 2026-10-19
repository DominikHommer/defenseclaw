// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeproto

import (
	"bytes"
	"encoding/json"
	"testing"
)

func tokenObservationFixture() *NativeTokenObservation {
	return &NativeTokenObservation{DiagnosticOnly: true, QueryComplete: true, PrimaryToken: true,
		UserSIDValid: true, UserMatchesPeer: true, IntegrityRID: 4096, TokenSessionID: 1,
		SessionMatchesPeer: true, TokenHandlesClosed: true}
}

func TestNativeTokenObservationIsStartedOnlyAndAbsentBytesStayExact(t *testing.T) {
	frame := fixtureFrame(t)
	frame.Kind = Started
	frame.Plan = nil
	absent, err := json.Marshal(frame)
	if err != nil || bytes.Contains(absent, []byte("native_token_observation")) {
		t.Fatal("absent changed bytes")
	}
	if _, err = Parse(absent); err != nil {
		t.Fatal("legacy Started refused")
	}
	frame.NativeTokenObservation = tokenObservationFixture()
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal("marshal")
	}
	if got, err := Parse(raw); err != nil || got.NativeTokenObservation == nil || *got.NativeTokenObservation != *frame.NativeTokenObservation {
		t.Fatal("diagnostic refused")
	}
	for _, kind := range []Kind{Prepare, Prepared, Launch, Output, Exited, Failed, Destroyed} {
		changed := frame
		changed.Kind = kind
		if changed.Validate() == nil {
			t.Fatal("diagnostic accepted on wrong kind")
		}
	}
	facts := *frame.NativeTokenObservation
	facts.UserMatchesPeer = false
	facts.SessionMatchesPeer = false
	facts.TokenIsAppContainer = true
	facts.IntegrityRID = ^uint32(0)
	facts.TokenSessionID = ^uint32(0)
	if facts.Validate() != nil {
		t.Fatal("facts used as admission policy")
	}
}

func TestNativeTokenObservationRejectsMissingNullAmbiguousOrPrivateFields(t *testing.T) {
	frame := fixtureFrame(t)
	frame.Kind = Started
	frame.Plan = nil
	frame.NativeTokenObservation = tokenObservationFixture()
	raw, _ := json.Marshal(frame)
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	var facts map[string]json.RawMessage
	_ = json.Unmarshal(object["native_token_observation"], &facts)
	if len(facts) != 13 {
		t.Fatal("field inventory")
	}
	for name := range facts {
		for _, missing := range []bool{true, false} {
			var mutated map[string]json.RawMessage
			_ = json.Unmarshal(object["native_token_observation"], &mutated)
			if missing {
				delete(mutated, name)
			} else {
				mutated[name] = json.RawMessage("null")
			}
			object["native_token_observation"], _ = json.Marshal(mutated)
			encoded, _ := json.Marshal(object)
			if _, err := Parse(encoded); err == nil {
				t.Fatal("missing/null fact accepted")
			}
		}
		// Restore exact baseline after every omitted/nullable field pair.
		_ = json.Unmarshal(raw, &object)
	}
	for _, row := range []struct{ key, value string }{
		{"diagnostic_only", "false"}, {"authorization_granted", "true"}, {"query_complete", "false"},
		{"primary_token", "false"}, {"user_sid_valid", "false"}, {"token_handles_closed", "false"},
		{"app_container_sid_present", "true"}, {"integrity_rid", "-1"}, {"token_session_id", "4294967296"},
		{"user_matches_peer", "0"}, {"sid", `"private"`},
	} {
		var modified map[string]json.RawMessage
		_ = json.Unmarshal(raw, &object)
		_ = json.Unmarshal(object["native_token_observation"], &modified)
		modified[row.key] = json.RawMessage(row.value)
		object["native_token_observation"], _ = json.Marshal(modified)
		encoded, _ := json.Marshal(object)
		if _, err := Parse(encoded); err == nil {
			t.Fatal("invalid/private fact accepted")
		}
	}
	for _, changed := range [][]byte{
		bytes.Replace(raw, []byte(`"diagnostic_only":true`), []byte(`"diagnostic_only":true,"diagnostic_only":true`), 1),
		bytes.Replace(raw, []byte(`"query_complete":true`), []byte(`"Query_complete":true`), 1),
		bytes.Replace(raw, []byte(`"native_token_observation":{`), []byte(`"native_token_observation":null,"ignored":{`), 1),
	} {
		if bytes.Equal(raw, changed) {
			t.Fatal("negative did not mutate")
		}
		if _, err := Parse(changed); err == nil {
			t.Fatal("ambiguous diagnostic accepted")
		}
	}
}

func TestNativeTokenObservationCannotBypassStartedCorrelation(t *testing.T) {
	for _, mutate := range []func(*Frame){func(f *Frame) { f.Request++ }, func(f *Frame) { f.Binding.SessionID = "other" }, func(f *Frame) { f.Sequence++ }} {
		prepare := fixtureFrame(t)
		c, _ := NewConversation(prepare.Binding)
		if c.Host(prepare) != nil {
			t.Fatal("prepare")
		}
		prepared := prepare
		prepared.Kind = Prepared
		prepared.Plan = nil
		if c.Bridge(prepared) != nil {
			t.Fatal("prepared")
		}
		launch := prepared
		launch.Kind = Launch
		launch.Sequence = 2
		launch.Request = 2
		if c.Host(launch) != nil {
			t.Fatal("launch")
		}
		started := launch
		started.Kind = Started
		started.NativeTokenObservation = tokenObservationFixture()
		mutate(&started)
		if c.Bridge(started) == nil || c.Phase() != PhaseClosed {
			t.Fatal("uncorrelated facts admitted")
		}
	}
}
