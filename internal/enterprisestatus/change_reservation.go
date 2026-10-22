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

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// A command that changes the trust anchors or a credential reserves room
// for its change event before it changes anything (Reserve) and holds the
// reservation until the event is written. Without it two commands could
// both find room, the first fill the spool, and the second be left with a
// change it cannot record. The spool lock (<StateDir>/change-events.lock)
// is held only while a command counts and reserves, or writes an event.
// A reservation is <StateDir>/change-reservations/<event_id>.json: the
// event the change records if its command ends before it writes one
// (failed, interrupted). Its command holds a lock on it. A reservation
// nobody holds belongs to a command that ended; the next writer moves its
// event into the spool, so the attempt is still reported.
//
// A credential change also marks its target right before it writes or
// removes it (MarkTarget): <event_id>.target names the file and which file
// was there (device and file number, or none). When the command ends after
// that and before its event, the next writer compares: another file there
// now, none where one was, or one where none was means the change was made,
// so it is recorded applied, not failed (interrupted). A mark carries no
// value and no hash of one.

const (
	changeSpoolLockName       = "change-events.lock"
	changeReservationsDirName = "change-reservations"
	changeTargetSuffix        = ".target"
	maxChangeTargetBytes      = 8 << 10
	// ChangeInterrupted is the reason code of a change whose command ended
	// before it recorded the outcome.
	ChangeInterrupted = "interrupted"
)

var (
	// changeSpoolLockWait bounds the wait for the spool lock, which a
	// writer holds for one count or one write.
	changeSpoolLockWait = 30 * time.Second
	changeSpoolLockPoll = 10 * time.Millisecond

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
	dir := filepath.Join(s.StateDir, changeReservationsDirName)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	if err := requireDirectory(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, ev.EventID+".json")
	file, err := openChangeFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*ChangeReservation, error) {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if _, err := file.Write(data); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if locked, err := tryLockChangeFile(file); err != nil || !locked {
		if err == nil {
			err = fmt.Errorf("cannot lock the change event reservation %s", path)
		}
		return fail(err)
	}
	return &ChangeReservation{spool: s, id: ev.EventID, path: path, file: file}, nil
}

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
	// Under the spool lock no writer can take the reservation for one whose
	// command ended between its unlock and its removal.
	if unlock, err := r.spool.lock(); err == nil {
		defer unlock()
	}
	r.drop()
}

func (r *ChangeReservation) drop() {
	r.abandon()
	_ = os.Remove(r.path)
	_ = os.Remove(changeTargetMarkPath(r.path))
}

// changeTarget is the file a change is about to write or remove, as it was
// before the change: absent, or present with this identity.
type changeTarget struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Device  uint64 `json:"device,omitempty"`
	File    uint64 `json:"file,omitempty"`
}

func changeTargetMarkPath(reservationPath string) string {
	return strings.TrimSuffix(reservationPath, ".json") + changeTargetSuffix
}

// MarkTarget records which file is at path (an absolute path) right before
// the change writes or removes it. The change is not made when this fails:
// an interruption after it could not be told from one before it.
func (r *ChangeReservation) MarkTarget(path string) error {
	if r == nil || r.file == nil {
		return errChangeReservationUsed
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("change target %q is not an absolute path", path)
	}
	mark, err := inspectChangeTarget(path)
	if err != nil {
		return fmt.Errorf("inspect the change target: %w", err)
	}
	data, err := json.Marshal(mark)
	if err != nil {
		return err
	}
	return configwrite.WriteFileDurable(changeTargetMarkPath(r.path), data, 0o600)
}

// TargetChanged reports whether the target MarkTarget recorded is no longer
// the file it saw: the write or removal took effect. It is false without a
// mark, and when the target cannot be inspected.
func (r *ChangeReservation) TargetChanged() bool {
	if r == nil {
		return false
	}
	return changeTargetChanged(changeTargetMarkPath(r.path))
}

func changeTargetChanged(markPath string) bool {
	file, err := openChangeFile(markPath, os.O_RDONLY)
	if err != nil {
		return false
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxChangeTargetBytes+1))
	if err != nil || len(raw) > maxChangeTargetBytes {
		return false
	}
	var mark changeTarget
	if json.Unmarshal(raw, &mark) != nil || !filepath.IsAbs(mark.Path) {
		return false
	}
	now, err := inspectChangeTarget(mark.Path)
	return err == nil && now != mark
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
	dir := filepath.Join(s.StateDir, changeReservationsDirName)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if id, mark := strings.CutSuffix(entry.Name(), changeTargetSuffix); mark && ValidChangeEventID(id) {
			// The mark of a reservation already settled or released.
			if _, err := os.Lstat(filepath.Join(dir, id+".json")); errors.Is(err, fs.ErrNotExist) {
				_ = os.Remove(filepath.Join(dir, entry.Name()))
			}
			continue
		}
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
		err = s.recordInterrupted(id, file, changeTargetMarkPath(path))
		unlockChangeFile(file)
		_ = file.Close()
		if err != nil {
			return held, err
		}
		_ = os.Remove(path)
		_ = os.Remove(changeTargetMarkPath(path))
	}
	return held, nil
}

// recordInterrupted writes the event of a reservation whose command ended,
// unless that command wrote its own (the same id) or the gateway already
// reported it: applied when its marked target changed (markPath), else the
// reserved failed (interrupted). A damaged reservation records nothing.
func (s ChangeSpool) recordInterrupted(id string, file *os.File, markPath string) error {
	if _, err := os.Lstat(filepath.Join(s.Dir, id+".json")); err == nil {
		return nil
	}
	if s.Reported != nil && s.Reported(id) {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxChangeEventBytes+1))
	if err != nil || len(raw) > maxChangeEventBytes {
		return nil
	}
	var ev ChangeEvent
	if json.Unmarshal(raw, &ev) != nil || ev.EventID != id || ev.Validate() != nil {
		return nil
	}
	if changeTargetChanged(markPath) {
		applied := ev
		applied.Outcome, applied.ReasonCode = ChangeApplied, ""
		if data, err := marshalChangeEvent(applied); err == nil {
			raw = data
		}
	}
	return s.writeEvent(id, raw)
}
