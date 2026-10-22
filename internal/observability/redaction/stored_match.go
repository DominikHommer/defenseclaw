// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// ErrStoredRecordMismatch refuses a replay whose rebuilt record is not the
// record the local store holds under its id.
var ErrStoredRecordMismatch = errors.New("observability: the rebuilt record is not the stored record")

// MatchStoredProjection checks that record, rebuilt to offer a stored
// occurrence again (observability.WithStoredReplay), is the record whose
// local projection stored holds (projected_record_json of its row). The
// local projection copies every member of the canonical record but its body
// and field classes byte for byte (the time, ids, outcome, severity,
// action, event, schema versions, correlation and provenance), so those
// must be equal. The body and its field classes must be equal too, except
// where the stored projection transformed a value (a <redacted ...> or
// <hashed ...> token) or removed a field of a class a profile changes: the
// store never held that value, so it cannot be compared. Metadata and
// identifier values (hashes, key ids, codes, ids, accounts) are kept as
// they are by every profile and are always compared. Only the stored
// projection is read, never the current redaction config or key, so a
// config reload or a key rotation does not change the answer.
func MatchStoredProjection(record observability.Record, stored []byte) error {
	if record.Signal() != observability.SignalLogs || len(stored) == 0 {
		return ErrStoredRecordMismatch
	}
	encoded, err := record.Bytes()
	if err != nil {
		return ErrStoredRecordMismatch
	}
	canonical, err := decodeStoredEnvelope(encoded)
	if err != nil {
		return ErrStoredRecordMismatch
	}
	projected, err := decodeStoredEnvelope(stored)
	if err != nil {
		return ErrStoredRecordMismatch
	}
	for key, value := range canonical {
		if key == "body" || key == "field_classes" {
			continue
		}
		if !bytes.Equal(value, projected[key]) {
			return ErrStoredRecordMismatch
		}
	}
	for key := range projected {
		if _, present := canonical[key]; !present && key != "projection" {
			return ErrStoredRecordMismatch
		}
	}
	var metadata ProjectionMetadata
	if json.Unmarshal(projected["projection"], &metadata) != nil || validateProjectionMetadata(metadata) != nil {
		return ErrStoredRecordMismatch
	}
	removed := metadata.RemovedFields > 0
	transformed := metadata.TransformedFields > 0 || metadata.FailureCount > 0

	var storedClasses map[string]observability.FieldClass
	if json.Unmarshal(projected["field_classes"], &storedClasses) != nil {
		return ErrStoredRecordMismatch
	}
	classes := record.FieldClasses()
	for pointer, class := range storedClasses {
		if canonicalClass, present := classes[pointer]; !present || canonicalClass != class {
			return ErrStoredRecordMismatch
		}
	}
	if len(storedClasses) != len(classes) && !removed {
		return ErrStoredRecordMismatch
	}

	canonicalBody, err := decodeStoredValue(canonical["body"])
	if err != nil {
		return ErrStoredRecordMismatch
	}
	storedBody, err := decodeStoredValue(projected["body"])
	if err != nil {
		return ErrStoredRecordMismatch
	}
	match := storedBodyMatch{classes: classes, removed: removed, transformed: transformed}
	if !match.value(canonicalBody, storedBody, "") {
		return ErrStoredRecordMismatch
	}
	return nil
}

func decodeStoredEnvelope(encoded []byte) (map[string]json.RawMessage, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope == nil {
		return nil, ErrStoredRecordMismatch
	}
	return envelope, nil
}

func decodeStoredValue(encoded json.RawMessage) (any, error) {
	if len(encoded) == 0 {
		return nil, ErrStoredRecordMismatch
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// storedBodyMatch compares a canonical body with the body of its stored
// projection. removed and transformed say whether the stored projection
// removed or transformed any field. Every profile keeps metadata and
// identifier values as they are (validateResolvedProfile), except a
// personal identifier a strict profile removes, so only a value of another
// class may differ by a token or be missing.
type storedBodyMatch struct {
	classes              map[string]observability.FieldClass
	removed, transformed bool
}

func (match storedBodyMatch) value(canonical, stored any, pointer string) bool {
	switch typed := canonical.(type) {
	case map[string]any:
		if len(typed) > 0 {
			object, ok := stored.(map[string]any)
			if !ok {
				return false
			}
			for key := range object {
				if _, present := typed[key]; !present {
					return false
				}
			}
			for key, child := range typed {
				childPointer := pointer + "/" + encodePointerToken(key)
				value, present := object[key]
				if !present {
					// A field the projection removed is not in it.
					if !match.removable(child, childPointer) {
						return false
					}
					continue
				}
				if !match.value(child, value, childPointer) {
					return false
				}
			}
			return true
		}
	case []any:
		if len(typed) > 0 {
			array, ok := stored.([]any)
			if !ok || len(array) != len(typed) {
				return false
			}
			for index, child := range typed {
				childPointer := pointer + "/" + strconv.Itoa(index)
				// A removed array element is null in the projection.
				if array[index] == nil && child != nil {
					if !match.removable(child, childPointer) {
						return false
					}
					continue
				}
				if !match.value(child, array[index], childPointer) {
					return false
				}
			}
			return true
		}
	}
	if reflect.DeepEqual(canonical, stored) {
		return true
	}
	text, isText := stored.(string)
	return match.transformed && isText && isRedactionOutput(text) && !match.keptAsIs(pointer)
}

// removable reports whether the stored projection may have removed the
// canonical value at pointer: every leaf under it is of a class a profile
// removes.
func (match storedBodyMatch) removable(canonical any, pointer string) bool {
	if !match.removed {
		return false
	}
	switch typed := canonical.(type) {
	case map[string]any:
		if len(typed) > 0 {
			for key, child := range typed {
				if !match.removable(child, pointer+"/"+encodePointerToken(key)) {
					return false
				}
			}
			return true
		}
	case []any:
		if len(typed) > 0 {
			for index, child := range typed {
				if !match.removable(child, pointer+"/"+strconv.Itoa(index)) {
					return false
				}
			}
			return true
		}
	}
	class := match.classes[pointer]
	return !match.keptAsIs(pointer) || (class == observability.FieldClassIdentifier && isPersonalIdentifierPointer(pointer))
}

// keptAsIs reports whether every profile keeps the value at pointer
// unchanged: a metadata or identifier value.
func (match storedBodyMatch) keptAsIs(pointer string) bool {
	class, ok := match.classes[pointer]
	return !ok || class == observability.FieldClassMetadata || class == observability.FieldClassIdentifier
}

// isRedactionOutput reports whether value holds a token the projection
// wrote in place of a value (token.go, hash_v1.go).
func isRedactionOutput(value string) bool {
	return strings.Contains(value, "<redacted type=") || strings.HasPrefix(value, "<hashed class=")
}
