// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func newTestSpool(t *testing.T) ChangeSpool {
	t.Helper()
	return ChangeSpool{Dir: filepath.Join(t.TempDir(), ChangeEventsDirName), StateDir: t.TempDir()}
}

func appliedSecretChange(t *testing.T, name string) ChangeEvent {
	t.Helper()
	ev, err := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeApplied, "")
	if err != nil {
		t.Fatal(err)
	}
	ev.SecretName = name
	return ev
}

func readSpool(t *testing.T, spool ChangeSpool) []ChangeEvent {
	t.Helper()
	var out []ChangeEvent
	for _, id := range ListChangeEventIDs(spool.Dir) {
		ev, err := ReadChangeEvent(filepath.Join(spool.Dir, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// Writers race for the last free place while changes are made: only the
// commands that reserved room make their change, and every one of them
// records it. Before reservations, each command checked the room on its
// own, so all of them passed and only the first one's event fit.
func TestChangeSpoolConcurrentChangesAtTheLimitAllRecord(t *testing.T) {
	shrinkChangeSpool(t, 2, 4)
	spool := newTestSpool(t)
	writeSpoolEvents(t, spool, 3)
	const writers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		changed  int
		refused  int
		lost     []error
		start    = make(chan struct{})
		outcomes = make([]ChangeEvent, writers)
	)
	for i := range outcomes {
		outcomes[i] = appliedSecretChange(t, "splunk-hec-token")
	}
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
			if err != nil {
				mu.Lock()
				defer mu.Unlock()
				if errors.Is(err, ErrChangeSpoolFull) {
					refused++
				} else {
					lost = append(lost, err)
				}
				return
			}
			// The change is made here, while the other writers race.
			if err := r.Write(outcomes[i]); err != nil {
				mu.Lock()
				lost = append(lost, err)
				mu.Unlock()
				return
			}
			mu.Lock()
			changed++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if len(lost) > 0 || changed != 1 || refused != writers-1 {
		t.Fatalf("changed=%d refused=%d lost=%v, want one change recorded and %d refused before changing", changed, refused, lost, writers-1)
	}
	if got := len(ListChangeEventIDs(spool.Dir)); got != 4 {
		t.Fatalf("spool holds %d events, want 4", got)
	}
}

// A held reservation keeps its place against a refusal, and Write fills
// the reserved place even when the spool is otherwise full.
func TestChangeReservationKeepsItsPlace(t *testing.T) {
	shrinkChangeSpool(t, 2, 3)
	spool := newTestSpool(t)
	writeSpoolEvents(t, spool, 2)
	r, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	refusal, err := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Write(refusal); !errors.Is(err, ErrChangeSpoolFull) {
		t.Fatalf("a refusal took the reserved place: %v", err)
	}
	if _, err := spool.Reserve(ChangeKindSecret, ChangeActionRemove, "otlp-token"); !errors.Is(err, ErrChangeSpoolFull) {
		t.Fatalf("a second change reserved the same place: %v", err)
	}
	applied, err := NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeApplied, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(applied); err != nil {
		t.Fatalf("write into the reserved place: %v", err)
	}
	if err := r.Write(applied); !errors.Is(err, errChangeReservationUsed) {
		t.Fatalf("a reservation was written twice: %v", err)
	}
	r.Release()
	events := readSpool(t, spool)
	if len(events) != 3 || events[2].EventID != r.id || events[2].Outcome != ChangeApplied {
		t.Fatalf("spool = %+v, want the applied install under the reservation id", events)
	}
	if entries, _ := os.ReadDir(spool.reservedDir()); len(entries) != 0 {
		t.Fatalf("reservations left: %v", entries)
	}
}

// Release gives the place back and records nothing.
func TestChangeReservationReleaseRecordsNothing(t *testing.T) {
	shrinkChangeSpool(t, 2, 1)
	spool := newTestSpool(t)
	r, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	r.Release()
	r.Release()
	if got := ListChangeEventIDs(spool.Dir); len(got) != 0 {
		t.Fatalf("a released reservation recorded %v", got)
	}
	again, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatalf("the released place was not given back: %v", err)
	}
	again.Release()
}

// A command that ends between its change and its event leaves its
// reservation unlocked; the next writer records it as an interrupted
// change with the credential name, once. A reservation whose command wrote
// its event before it ended adds no second record.
func TestChangeSpoolRecordsTheReservationOfACommandThatEnded(t *testing.T) {
	spool := newTestSpool(t)
	ended, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	ended.abandon() // The process stopped after the change.
	written, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeApplied, "")
	if err != nil {
		t.Fatal(err)
	}
	applied.EventID = written.id
	data, err := marshalChangeEvent(applied)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.writeEvent(written.id, data); err != nil {
		t.Fatal(err)
	}
	written.abandon() // The process stopped after the event, before the cleanup.
	held, err := spool.Reserve(ChangeKindSecret, ChangeActionRemove, "otlp-token")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	events := readSpool(t, spool)
	if len(events) != 2 {
		t.Fatalf("spool = %+v, want the interrupted set and the applied install", events)
	}
	interrupted := events[0]
	if interrupted.EventID != ended.id || interrupted.Kind != ChangeKindSecret || interrupted.Outcome != ChangeFailed ||
		interrupted.ReasonCode != ChangeInterrupted || interrupted.SecretName != "splunk-hec-token" {
		t.Fatalf("interrupted change = %+v", interrupted)
	}
	if events[1].EventID != written.id || events[1].Outcome != ChangeApplied {
		t.Fatalf("applied install = %+v", events[1])
	}
	entries, err := os.ReadDir(spool.reservedDir())
	if err != nil || len(entries) != 1 || entries[0].Name() != held.id+".json" {
		t.Fatalf("reservations = %v (%v), want only the held one", entries, err)
	}
}

// The gateway, which only reads the spool, finds the reservation of a
// command that ended after its change (the change may have been made) and
// nothing else: not a held one, not one whose command wrote its event or
// released it, not one whose event is in the spool, not an empty or a
// damaged one. Before, such a reservation sat in the root-only lifecycle
// folder until the next change command, so a gateway restart alone never
// reported it.
func TestEndedChangeReservationsAreTheCommandsThatEndedAfterTheirChange(t *testing.T) {
	spool := newTestSpool(t)
	held, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	written, err := spool.Reserve(ChangeKindTrustAnchors, ChangeActionInstall, "")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeApplied, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := written.Write(applied); err != nil {
		t.Fatal(err)
	}
	released, err := spool.Reserve(ChangeKindSecret, ChangeActionRemove, "otlp-token")
	if err != nil {
		t.Fatal(err)
	}
	released.Release()
	// The last reservation: every Reserve moves the ended ones into the
	// spool first.
	ended, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token")
	if err != nil {
		t.Fatal(err)
	}
	ended.abandon() // The process stopped after the change.
	// A command that stopped after its event, before the cleanup; one that
	// stopped before its reservation held its event; a damaged reservation.
	beforeCleanup, err := NewChangeEvent(ChangeKindTrustAnchors, ChangeActionInstall, ChangeFailed, ChangeInterrupted)
	if err != nil {
		t.Fatal(err)
	}
	provisional, err := marshalChangeEvent(beforeCleanup)
	if err != nil {
		t.Fatal(err)
	}
	applied.EventID = beforeCleanup.EventID
	data, err := marshalChangeEvent(applied)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.writeEvent(beforeCleanup.EventID, data); err != nil {
		t.Fatal(err)
	}
	empty, _ := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeFailed, ChangeInterrupted)
	damaged, _ := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeFailed, ChangeInterrupted)
	for id, body := range map[string]string{beforeCleanup.EventID: string(provisional), empty.EventID: "",
		damaged.EventID: `{"event_id":"` + damaged.EventID + `"}`} {
		if err := os.WriteFile(filepath.Join(spool.reservedDir(), id+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := EndedChangeReservations(spool.Dir)
	if len(got) != 1 || got[0].EventID != ended.id || got[0].Outcome != ChangeFailed || got[0].ReasonCode != ChangeInterrupted ||
		got[0].SecretName != "splunk-hec-token" {
		t.Fatalf("ended reservations = %+v, want only the interrupted set %s", got, ended.id)
	}
	// Reading takes nothing: the held reservation keeps its lock, and the
	// next writer still moves the ended one into the spool.
	if err := held.Write(applied); err != nil {
		t.Fatalf("the held reservation lost its place: %v", err)
	}
	refusal, err := NewChangeEvent(ChangeKindSecret, ChangeActionSet, ChangeRefused, "invalid_arguments")
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Write(refusal); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(spool.reservedDir()); len(entries) != 0 {
		t.Fatalf("reservations left after the next writer: %v", entries)
	}
	ids := ListChangeEventIDs(spool.Dir)
	found := false
	for _, id := range ids {
		found = found || id == ended.id
	}
	if !found {
		t.Fatalf("spool = %v, want the ended reservation moved in", ids)
	}
	if got := EndedChangeReservations(spool.Dir); len(got) != 0 {
		t.Fatalf("ended reservations after the next writer = %+v", got)
	}
	if got := EndedChangeReservations(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Fatalf("a missing spool has ended reservations: %+v", got)
	}
}

// The spool needs its existing state directory: without one nothing is
// written.
func TestChangeSpoolNeedsItsStateDirectory(t *testing.T) {
	spool := ChangeSpool{Dir: filepath.Join(t.TempDir(), ChangeEventsDirName)}
	if err := spool.Write(appliedSecretChange(t, "splunk-hec-token")); err == nil {
		t.Fatal("wrote without a state directory")
	}
	spool.StateDir = filepath.Join(t.TempDir(), "missing")
	if _, err := spool.Reserve(ChangeKindSecret, ChangeActionSet, "splunk-hec-token"); err == nil {
		t.Fatal("reserved in a missing state directory")
	}
}
