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
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// A change event is the record a root command leaves when it changes the
// trust anchors or a protected credential of a standalone managed device
// (enterprise bundle anchors install, enterprise windows ensure
// --trust-anchors, enterprise secret set and remove), including a refused
// or failed change. The command writes one file per change into
// <etc>/bundles/change-events/, readable by root (Administrators and
// SYSTEM on Windows) and the gateway service account only; the gateway
// reports each as one audit event (config.trust_anchors.changed,
// config.secret.changed, config.secret.change_failed) when it runs, so a
// change made while it was stopped is reported at its next start. The
// gateway marks each event it reported under its data directory
// (ReportedMarkersDirName); the command removes only marked events, so an
// event is never lost before it is reported. A change event carries
// hashes, key ids, a credential name and closed codes; it never carries a
// credential value or a hash of one.

const (
	// ChangeEventsDirName is the change spool under <etc>/bundles.
	ChangeEventsDirName = "change-events"
	// ChangeEventSchemaVersion is the change event schema.
	ChangeEventSchemaVersion = 1
	// ReportedMarkersDirName is the folder under the gateway data directory
	// where the gateway marks each bundle receipt and change event it
	// reported (one file named by each id).
	ReportedMarkersDirName = "bundle-receipt.reported.d"

	maxChangeEventBytes = 16 << 10
	maxChangeKeyIDs     = 64
)

// Change kinds, actions and outcomes.
const (
	ChangeKindTrustAnchors = "trust_anchors"
	ChangeKindSecret       = "secret"

	ChangeActionInstall = "install"
	ChangeActionSet     = "set"
	ChangeActionRemove  = "remove"

	// ChangeApplied changed the anchor file or the credential; ChangeRefused
	// was stopped before anything was written; ChangeFailed was attempted
	// and did not complete.
	ChangeApplied = "applied"
	ChangeRefused = "refused"
	ChangeFailed  = "failed"
)

var (
	changeEventIDPattern = regexp.MustCompile(`^c-[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	changeCodePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	changeSHA256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	changeKeyIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	changeSecretPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	changeActorPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

	// maxReportedChangeEvents is how many reported events the spool keeps:
	// a write removes the oldest reported events beyond it.
	maxReportedChangeEvents = 256
	// maxPendingChangeEvents bounds the events the gateway has not reported:
	// past it a write is refused (ErrChangeSpoolFull), and no unreported
	// event is removed to make room.
	maxPendingChangeEvents = 4096
)

// ErrChangeSpoolFull refuses a change event while the spool holds
// maxPendingChangeEvents events the gateway has not reported.
var ErrChangeSpoolFull = errors.New("the change spool is full of events the gateway has not reported yet; start the gateway so it reports them")

// ChangeReported reports whether the gateway with the data directory
// dataDir has marked change event id reported.
func ChangeReported(dataDir, id string) bool {
	if strings.TrimSpace(dataDir) == "" || !ValidChangeEventID(id) {
		return false
	}
	info, err := os.Lstat(filepath.Join(dataDir, ReportedMarkersDirName, id))
	return err == nil && info.Mode().IsRegular()
}

// ChangeEvent is one change-events/<event_id>.json.
type ChangeEvent struct {
	SchemaVersion int    `json:"schema_version"`
	EventID       string `json:"event_id"`
	Kind          string `json:"kind"`
	Action        string `json:"action"`
	Outcome       string `json:"outcome"`
	// ReasonCode is the errors[].code of a refused or failed change.
	ReasonCode string `json:"reason_code,omitempty"`
	// Actor is the local OS account that ran the command
	// (configwrite.CurrentOSActor).
	Actor string `json:"actor,omitempty"`
	Time  string `json:"time"`
	// SHA256 and PreviousSHA256 are the installed and the replaced anchor
	// file; KeyIDsAdded and KeyIDsRemoved the signing keys that changed.
	SHA256         string   `json:"sha256,omitempty"`
	PreviousSHA256 string   `json:"previous_sha256,omitempty"`
	KeyIDsAdded    []string `json:"key_ids_added,omitempty"`
	KeyIDsRemoved  []string `json:"key_ids_removed,omitempty"`
	// SecretName is the credential --name; a name the command refused is
	// left out.
	SecretName string `json:"secret_name,omitempty"`
}

// ChangeEventsDir is the change spool for the configuration directory
// configDir (the directory of config.yaml).
func ChangeEventsDir(configDir string) string {
	return filepath.Join(configDir, "bundles", ChangeEventsDirName)
}

// ValidChangeEventID permits only c-<ULID> change event ids.
func ValidChangeEventID(id string) bool { return changeEventIDPattern.MatchString(id) }

// ValidChangeSecretName reports whether name may be recorded as a
// credential name.
func ValidChangeSecretName(name string) bool { return changeSecretPattern.MatchString(name) }

// Validate checks every field against its closed form.
func (ev ChangeEvent) Validate() error {
	switch {
	case ev.SchemaVersion != ChangeEventSchemaVersion:
		return fmt.Errorf("change event schema_version %d is not %d", ev.SchemaVersion, ChangeEventSchemaVersion)
	case !ValidChangeEventID(ev.EventID):
		return errors.New("change event id is not c-<ULID>")
	case ev.Outcome != ChangeApplied && ev.Outcome != ChangeRefused && ev.Outcome != ChangeFailed:
		return fmt.Errorf("change event outcome %q is not registered", ev.Outcome)
	case ev.Outcome == ChangeApplied && ev.ReasonCode != "":
		return errors.New("an applied change event has no reason code")
	case ev.Outcome != ChangeApplied && !changeCodePattern.MatchString(ev.ReasonCode):
		return errors.New("a refused or failed change event needs a reason code")
	case ev.Actor != "" && !changeActorPattern.MatchString(ev.Actor):
		return errors.New("change event actor is not an OS actor")
	}
	if _, err := time.Parse(time.RFC3339Nano, ev.Time); err != nil {
		return errors.New("change event time is not RFC 3339")
	}
	switch ev.Kind {
	case ChangeKindTrustAnchors:
		if ev.Action != ChangeActionInstall || ev.SecretName != "" {
			return errors.New("a trust anchor change event is an install and names no credential")
		}
		for _, sum := range []string{ev.SHA256, ev.PreviousSHA256} {
			if sum != "" && !changeSHA256Pattern.MatchString(sum) {
				return errors.New("change event sha256 is not 64 lowercase hex")
			}
		}
		for _, ids := range [][]string{ev.KeyIDsAdded, ev.KeyIDsRemoved} {
			if len(ids) > maxChangeKeyIDs {
				return errors.New("change event names too many key ids")
			}
			for _, id := range ids {
				if !changeKeyIDPattern.MatchString(id) {
					return errors.New("change event key id is not a key id")
				}
			}
		}
	case ChangeKindSecret:
		if ev.Action != ChangeActionSet && ev.Action != ChangeActionRemove {
			return fmt.Errorf("credential change event action %q is not set or remove", ev.Action)
		}
		if ev.SHA256 != "" || ev.PreviousSHA256 != "" || len(ev.KeyIDsAdded) > 0 || len(ev.KeyIDsRemoved) > 0 {
			return errors.New("a credential change event carries no hash or key id")
		}
		if ev.SecretName != "" && !ValidChangeSecretName(ev.SecretName) {
			return errors.New("change event credential name is not a credential name")
		}
		if ev.Outcome == ChangeApplied && ev.SecretName == "" {
			return errors.New("an applied credential change event names the credential")
		}
	default:
		return fmt.Errorf("change event kind %q is not registered", ev.Kind)
	}
	return nil
}

// NewChangeEvent fills the schema version, a new event id, the time and the
// actor of a change made now by this process.
func NewChangeEvent(kind, action, outcome, reasonCode string) (ChangeEvent, error) {
	at := time.Now().UTC()
	id, err := newChangeEventID(at, rand.Reader)
	if err != nil {
		return ChangeEvent{}, err
	}
	ev := ChangeEvent{SchemaVersion: ChangeEventSchemaVersion, EventID: id, Kind: kind, Action: action,
		Outcome: outcome, Time: at.Format(time.RFC3339Nano)}
	if outcome != ChangeApplied {
		ev.ReasonCode = reasonCode
		if !changeCodePattern.MatchString(ev.ReasonCode) {
			ev.ReasonCode = "change_failed"
		}
	}
	if actor := configwrite.CurrentOSActor(); changeActorPattern.MatchString(actor) {
		ev.Actor = actor
	}
	return ev, nil
}

// ChangedKeyIDs returns the key ids next adds to and removes from previous,
// each sorted and without duplicates.
func ChangedKeyIDs(previous, next []string) (added, removed []string) {
	had, has := map[string]bool{}, map[string]bool{}
	for _, id := range previous {
		had[id] = true
	}
	for _, id := range next {
		has[id] = true
	}
	for id := range has {
		if !had[id] {
			added = append(added, id)
		}
	}
	for id := range had {
		if !has[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// ChangeSpool writes change events. Reported tells which events the
// gateway has reported (ChangeReported); nil counts none as reported.
// Prepare creates (or repairs) the spool directory with its owner and
// access, and Publish sets the owner and access of one written file; both
// are platform hooks. A nil hook does nothing.
type ChangeSpool struct {
	Dir      string
	Reported func(id string) bool
	Prepare  func(dir string) error
	Publish  func(path string) error
}

// Ready prepares the spool directory, removes the oldest reported events
// beyond maxReportedChangeEvents and checks that one more event fits. A
// command calls it before it changes anything, so a change it could not
// record is refused rather than made unaudited.
func (s ChangeSpool) Ready() error {
	if s.Prepare != nil {
		if err := s.Prepare(s.Dir); err != nil {
			return err
		}
	} else if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return err
	}
	info, err := os.Lstat(s.Dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("change events directory is not a regular directory: %s", s.Dir)
	}
	return s.prune()
}

// Write validates ev and writes it as <Dir>/<event_id>.json (Ready first).
func (s ChangeSpool) Write(ev ChangeEvent) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	if err := s.Ready(); err != nil {
		return err
	}
	path := filepath.Join(s.Dir, ev.EventID+".json")
	if err := configwrite.WriteFileDurable(path, append(data, '\n'), 0o640); err != nil {
		return err
	}
	if s.Publish != nil {
		if err := s.Publish(path); err != nil {
			_ = os.Remove(path)
			return err
		}
	}
	return nil
}

// prune makes room for one more event: it removes the oldest reported
// events while the spool holds maxReportedChangeEvents or more, and never
// an event the gateway has not reported. It returns ErrChangeSpoolFull when
// maxPendingChangeEvents events wait to be reported. The ids are ULIDs, so
// name order is time order.
func (s ChangeSpool) prune() error {
	ids := ListChangeEventIDs(s.Dir)
	var reported []string
	pending := 0
	for _, id := range ids {
		if s.Reported != nil && s.Reported(id) {
			reported = append(reported, id)
		} else {
			pending++
		}
	}
	for total := len(ids); total >= maxReportedChangeEvents && len(reported) > 0; total-- {
		_ = os.Remove(filepath.Join(s.Dir, reported[0]+".json"))
		reported = reported[1:]
	}
	if pending >= maxPendingChangeEvents {
		return ErrChangeSpoolFull
	}
	return nil
}

// ListChangeEventIDs lists the change event ids in dir, oldest first. A
// link or a file that is not named <c-ULID>.json is skipped.
func ListChangeEventIDs(dir string) []string {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var ids []string
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if ok && ValidChangeEventID(id) && entry.Type().IsRegular() {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ReadChangeEvent reads one change event. It refuses a link, a file over 16
// KiB and an event that does not validate.
func ReadChangeEvent(path string) (ChangeEvent, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ChangeEvent{}, err
	}
	if !info.Mode().IsRegular() {
		return ChangeEvent{}, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return ChangeEvent{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxChangeEventBytes+1))
	if err != nil {
		return ChangeEvent{}, err
	}
	if len(raw) > maxChangeEventBytes {
		return ChangeEvent{}, fmt.Errorf("%s is larger than %d bytes", path, maxChangeEventBytes)
	}
	var ev ChangeEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return ChangeEvent{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := ev.Validate(); err != nil {
		return ChangeEvent{}, fmt.Errorf("%s: %w", path, err)
	}
	return ev, nil
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newChangeEventID returns c-<ULID> for t with 80 random bits from r.
func newChangeEventID(t time.Time, r io.Reader) (string, error) {
	ms := t.UnixMilli()
	if ms < 0 || ms >= 1<<48 {
		return "", errors.New("time outside the ULID range")
	}
	var id [16]byte
	for i := 0; i < 6; i++ {
		id[i] = byte(ms >> (8 * (5 - i)))
	}
	if _, err := io.ReadFull(r, id[6:]); err != nil {
		return "", err
	}
	// 128 bits as 26 base-32 digits, most significant first (the first
	// digit holds 3 bits, so it is 0-7).
	out := make([]byte, 26)
	var acc uint64
	bits, pos := 0, 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(id[i]) << bits
		bits += 8
		for bits >= 5 && pos >= 0 {
			out[pos] = crockford[acc&31]
			acc >>= 5
			bits -= 5
			pos--
		}
	}
	if pos >= 0 {
		out[pos] = crockford[acc&31]
	}
	return "c-" + string(out), nil
}
