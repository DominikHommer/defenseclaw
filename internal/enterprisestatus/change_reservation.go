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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A command that changes the trust anchors or a credential reserves room
// for its change event before it changes anything (Reserve) and holds the
// reservation until the event is written. Without it two commands could
// both find room, the first fill the spool, and the second be left with a
// change it cannot record. The spool lock (<StateDir>/change-events.lock)
// is held only while a command counts and reserves, or writes an event.
// A reservation is <Dir>/reserved/<event_id>.json, with the access of the
// spool: the event the change records if its command ends before it
// writes one (failed, interrupted). Its command holds a lock on it from
// before the event is in it until the file is emptied. A reservation
// nobody holds belongs to a command that ended. The gateway reports its
// event at its next poll, a restart included (EndedChangeReservations),
// and the next writer moves it into the spool, so the attempt is reported
// even when no other command runs.

const (
	changeSpoolLockName = "change-events.lock"
	// ChangeReservedDirName is the folder of the reservations in the spool.
	ChangeReservedDirName = "reserved"
	// ChangeInterrupted is the reason code of a change whose command ended
	// before it recorded the outcome.
	ChangeInterrupted = "interrupted"
)

var (
	// changeSpoolLockWait bounds the wait for the spool lock, which a
	// writer holds for one count or one write.
	changeSpoolLockWait = 30 * time.Second
	changeSpoolLockPoll = 10 * time.Millisecond
	// changeReservationLockWait bounds the wait for the lock of a new
	// reservation, which the gateway holds only while it reads it.
	changeReservationLockWait = time.Second

	errChangeSpoolBusy       = errors.New("another command is writing a change event; try again")
	errChangeReservationUsed = errors.New("the change event reservation was already used")
)

// ChangeReservation is the room in the spool for the event of one change in
// progress.
type ChangeReservation struct {
	spool ChangeSpool
	id    string
	path  string
	file  *os.File
}

// Reserve holds room for the event of a change about to be made; kind,
// action and name (the credential, "" for none) say what it changes. It
// returns ErrChangeSpoolFull when the spool cannot take one more event.
// The command then writes the outcome with Write, or calls Release when it
// changed nothing.
func (s ChangeSpool) Reserve(kind, action, name string) (*ChangeReservation, error) {
	ev, err := NewChangeEvent(kind, action, ChangeFailed, ChangeInterrupted)
	if err != nil {
		return nil, err
	}
	if kind == ChangeKindSecret && ValidChangeSecretName(name) {
		ev.SecretName = name
	}
	data, err := marshalChangeEvent(ev)
	if err != nil {
		return nil, err
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.ready(); err != nil {
		return nil, err
	}
	dir := s.reservedDir()
	if err := s.prepareDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, ev.EventID+".json")
	file, err := openChangeFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*ChangeReservation, error) {
		unlockChangeFile(file)
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	// Locked before the event is in it: a reader takes the lock first, so
	// it finds a reservation in progress held, or empty.
	if err := lockNewChangeFile(file, path); err != nil {
		return fail(err)
	}
	if s.Publish != nil {
		if err := s.Publish(path); err != nil {
			return fail(err)
		}
	}
	if _, err := file.Write(data); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	return &ChangeReservation{spool: s, id: ev.EventID, path: path, file: file}, nil
}

// lockNewChangeFile locks a reservation just created. Only a reader that
// found it before its event was written can hold the lock, and only for
// that read.
func lockNewChangeFile(file *os.File, path string) error {
	deadline := time.Now().Add(changeReservationLockWait)
	for {
		locked, err := tryLockChangeFile(file)
		if err != nil {
			return err
		}
		if locked {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("cannot lock the change event reservation %s", path)
		}
		time.Sleep(changeSpoolLockPoll)
	}
}

func (s ChangeSpool) reservedDir() string { return filepath.Join(s.Dir, ChangeReservedDirName) }

// Write records ev, the outcome of the change, in the reserved room; the
// event takes the id of the reservation. When it cannot, the reservation is
// left for the next writer, which records the change as interrupted.
func (r *ChangeReservation) Write(ev ChangeEvent) error {
	if r == nil || r.file == nil {
		return errChangeReservationUsed
	}
	ev.EventID = r.id
	data, err := marshalChangeEvent(ev)
	if err != nil {
		r.abandon()
		return err
	}
	unlock, err := r.spool.lock()
	if err != nil {
		r.abandon()
		return err
	}
	defer unlock()
	if err := r.spool.writeEvent(r.id, data); err != nil {
		r.abandon()
		return err
	}
	r.drop()
	return nil
}

// Release gives the room back when the change was not made and records
// nothing. It does nothing after Write.
func (r *ChangeReservation) Release() {
	if r == nil || r.file == nil {
		return
	}
	r.drop()
}

// drop empties the reservation before it unlocks and removes it: a reader
// that takes the lock in between finds no event in it and records nothing.
// A removal that fails (Windows, while the gateway has it open) leaves an
// empty file, which the next writer removes.
func (r *ChangeReservation) drop() {
	_ = r.file.Truncate(0)
	r.abandon()
	_ = os.Remove(r.path)
}

func (r *ChangeReservation) abandon() {
	unlockChangeFile(r.file)
	_ = r.file.Close()
	r.file = nil
}

// lock takes the spool lock, waiting at most changeSpoolLockWait.
func (s ChangeSpool) lock() (func(), error) {
	if strings.TrimSpace(s.StateDir) == "" {
		return nil, errors.New("the change spool has no state directory")
	}
	if err := requireDirectory(s.StateDir); err != nil {
		return nil, err
	}
	file, err := openChangeFile(filepath.Join(s.StateDir, changeSpoolLockName), os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(changeSpoolLockWait)
	for {
		locked, err := tryLockChangeFile(file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		if locked {
			return func() {
				unlockChangeFile(file)
				_ = file.Close()
			}, nil
		}
		if !time.Now().Before(deadline) {
			_ = file.Close()
			return nil, errChangeSpoolBusy
		}
		time.Sleep(changeSpoolLockPoll)
	}
}

func requireDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular directory", dir)
	}
	return nil
}

// settleReservations counts the reservations still held and records the
// event of every other one, whose command ended before it wrote its own.
// The caller holds the spool lock.
func (s ChangeSpool) settleReservations() (held int, err error) {
	dir := s.reservedDir()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !ValidChangeEventID(id) || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := openChangeFile(path, os.O_RDWR)
		if err != nil {
			held++
			continue
		}
		locked, err := tryLockChangeFile(file)
		if err != nil || !locked {
			_ = file.Close()
			held++
			continue
		}
		err = s.recordInterrupted(id, file)
		unlockChangeFile(file)
		_ = file.Close()
		if err != nil {
			return held, err
		}
		_ = os.Remove(path)
	}
	return held, nil
}

// recordInterrupted writes the event of a reservation whose command ended,
// unless that command wrote its own (the same id) or the gateway already
// reported it. A damaged reservation records nothing.
func (s ChangeSpool) recordInterrupted(id string, file *os.File) error {
	if _, err := os.Lstat(filepath.Join(s.Dir, id+".json")); err == nil {
		return nil
	}
	if s.Reported != nil && s.Reported(id) {
		return nil
	}
	raw, _, ok := readReservation(file, id)
	if !ok {
		return nil
	}
	return s.writeEvent(id, raw)
}

// readReservation reads the event of reservation id from file. An emptied
// reservation (its command wrote its event or changed nothing) and one
// that does not validate are not ok.
func readReservation(file *os.File, id string) ([]byte, ChangeEvent, bool) {
	raw, err := io.ReadAll(io.LimitReader(file, maxChangeEventBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxChangeEventBytes {
		return nil, ChangeEvent{}, false
	}
	var ev ChangeEvent
	if json.Unmarshal(raw, &ev) != nil || ev.EventID != id || ev.Validate() != nil {
		return nil, ChangeEvent{}, false
	}
	return raw, ev, true
}

// EndedChangeReservations is for the gateway, which reads the change spool
// dir and cannot write it. It returns, oldest first, the event of every
// reservation whose command ended before it wrote its outcome and whose
// event is not in the spool: the change it held room for may have been
// made, so it is reported as failed (interrupted) at the gateway's next
// poll, even when no later command moves it into the spool. A reservation
// still held, an emptied one and one that does not validate are skipped.
// The writer that settles the reservation later keeps its id, so the
// gateway reports it once.
func EndedChangeReservations(dir string) []ChangeEvent {
	reserved := filepath.Join(dir, ChangeReservedDirName)
	if requireDirectory(dir) != nil || requireDirectory(reserved) != nil {
		return nil
	}
	entries, err := os.ReadDir(reserved)
	if err != nil {
		return nil
	}
	var out []ChangeEvent
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !ValidChangeEventID(id) || !entry.Type().IsRegular() {
			continue
		}
		if ev, ok := readEndedReservation(dir, filepath.Join(reserved, entry.Name()), id); ok {
			out = append(out, ev)
		}
	}
	return out
}

func readEndedReservation(dir, path, id string) (ChangeEvent, bool) {
	file, err := openChangeFile(path, os.O_RDONLY)
	if err != nil {
		return ChangeEvent{}, false
	}
	defer file.Close()
	if locked, err := tryLockChangeFile(file); err != nil || !locked {
		return ChangeEvent{}, false
	}
	defer unlockChangeFile(file)
	// Its command writes the event into the spool before it lets go of the
	// reservation, so an event there is the outcome.
	if _, err := os.Lstat(filepath.Join(dir, id+".json")); !errors.Is(err, fs.ErrNotExist) {
		return ChangeEvent{}, false
	}
	_, ev, ok := readReservation(file, id)
	return ev, ok
}
