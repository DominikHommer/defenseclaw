// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// The persist phase of a replayable spool item records the destinations its
// local row owes before the row commits (RuntimeV8Spool.Intent), one file per
// stable occurrence id beside the audit database. The confirm phase reads it
// back, so neither a restart nor a later route change (logs turned off, a
// destination removed or re-scoped) drops an earlier remote obligation or
// waits on one that never existed. A file that cannot be read or validated
// keeps the item pending. It is removed once the delivery is confirmed.

const (
	spoolObligationsDirName  = "spool-delivery-obligations"
	spoolObligationsSchema   = 1
	maxSpoolObligationsBytes = 16 << 10
	maxSpoolObligations      = 64
)

type spoolObligationsFile struct {
	SchemaVersion int      `json:"schema_version"`
	Destinations  []string `json:"destinations"`
}

func (l *Logger) spoolObligationsPath(occurrenceID string) (string, error) {
	if l == nil || l.store == nil || !filepath.IsAbs(l.store.dbPath) {
		return "", errors.New("audit: spool delivery obligations need an on-disk audit store")
	}
	parsed, err := uuid.Parse(occurrenceID)
	if err != nil || parsed.String() != occurrenceID {
		return "", errors.New("audit: spool occurrence id is not a canonical uuid")
	}
	return filepath.Join(filepath.Dir(l.store.dbPath), spoolObligationsDirName, occurrenceID+".json"), nil
}

// spoolDelivery is the RuntimeV8Spool of one phase of occurrenceID.
func (l *Logger) spoolDelivery(occurrenceID string, confirm bool) (RuntimeV8Spool, error) {
	path, err := l.spoolObligationsPath(occurrenceID)
	if err != nil {
		return RuntimeV8Spool{}, err
	}
	if !confirm {
		return RuntimeV8Spool{Intent: func(destinations []string) error {
			return writeSpoolObligations(path, destinations)
		}}, nil
	}
	destinations, known, err := readSpoolObligations(path)
	if err != nil {
		return RuntimeV8Spool{}, err
	}
	return RuntimeV8Spool{Confirm: true, Obligations: destinations, Known: known}, nil
}

func writeSpoolObligations(path string, destinations []string) error {
	names := append([]string{}, destinations...)
	sort.Strings(names)
	if err := validSpoolObligations(names); err != nil {
		return err
	}
	raw, err := json.Marshal(spoolObligationsFile{SchemaVersion: spoolObligationsSchema, Destinations: names})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return safefile.WritePrivate(path, append(raw, '\n'))
}

// readSpoolObligations returns the recorded destinations; known is false
// when the row was committed without a record (a build before this one).
func readSpoolObligations(path string) ([]string, bool, error) {
	raw, err := safefile.ReadRegularFileBounded(path, maxSpoolObligationsBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("audit: read spool delivery obligations: %w", err)
	}
	var file spoolObligationsFile
	if err := json.Unmarshal(raw, &file); err != nil || file.SchemaVersion != spoolObligationsSchema {
		return nil, false, errors.New("audit: spool delivery obligations are not readable")
	}
	if !sort.StringsAreSorted(file.Destinations) {
		return nil, false, errors.New("audit: spool delivery obligations are not canonical")
	}
	if err := validSpoolObligations(file.Destinations); err != nil {
		return nil, false, err
	}
	return file.Destinations, true, nil
}

func validSpoolObligations(sorted []string) error {
	if len(sorted) > maxSpoolObligations {
		return errors.New("audit: too many spool delivery obligations")
	}
	for index, name := range sorted {
		if !observability.IsStableToken(name) || (index > 0 && sorted[index-1] == name) {
			return errors.New("audit: spool delivery obligation names a destination that is not a stable token")
		}
	}
	return nil
}

func (l *Logger) forgetSpoolObligations(occurrenceID string) {
	if path, err := l.spoolObligationsPath(occurrenceID); err == nil {
		_ = os.Remove(path)
	}
}
