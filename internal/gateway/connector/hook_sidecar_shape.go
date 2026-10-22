// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// The shapes of the hooks/.hookcfg files every reader agrees on: the native
// Windows hook (readHookSidecar), status (fail_mode.py), the shared Unix
// hooks (_hardening.sh) and the writers here, which must never turn state a
// reader closes on into state it opens on when they rewrite it.

// hookSidecarJSONFields are the top-level fields of the JSON sidecar.
var hookSidecarJSONFields = [...]string{"version", "gateway_addr", "fail_modes", "legacy_fail_mode"}

// HookSidecarJSONAmbiguous reports a JSON sidecar that names a key twice in
// one object, or a top-level key that names a sidecar field in another case.
// Readers take the last of two keys and encoding/json folds case, so such a
// document reads differently to each reader, and a rewrite would settle it
// either way: it is malformed state. data must be valid JSON.
func HookSidecarJSONAmbiguous(data []byte) bool {
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) == nil {
		for key := range doc {
			for _, field := range hookSidecarJSONFields {
				if key != field && strings.EqualFold(key, field) {
					return true
				}
			}
		}
	}
	return jsonDuplicateKey(data)
}

// hookSidecarJSONMaxNesting bounds the nesting jsonDuplicateKey walks: the
// writers nest two levels, and encoding/json's own limit is not the same in
// every Go release.
const hookSidecarJSONMaxNesting = 10000

// jsonDuplicateKey reports an object of data that names a key twice, data
// nested deeper than hookSidecarJSONMaxNesting, or data that is not JSON. It
// walks the tokens without recursion, so the nesting of the document never
// grows the stack.
func jsonDuplicateKey(data []byte) bool {
	type frame struct {
		keys      map[string]struct{} // nil for an array
		expectKey bool
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber() // a number too large for a float64 is still JSON
	var stack []*frame
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return false
		}
		if err != nil {
			return true
		}
		var top *frame
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if top != nil && top.keys != nil {
					top.expectKey = true // this container is the value
				}
				next := &frame{}
				if delim == '{' {
					next.keys = map[string]struct{}{}
					next.expectKey = true
				}
				stack = append(stack, next)
				if len(stack) > hookSidecarJSONMaxNesting {
					return true
				}
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || top.keys == nil {
			continue
		}
		if top.expectKey {
			key, _ := token.(string)
			if _, seen := top.keys[key]; seen {
				return true
			}
			top.keys[key] = struct{}{}
			top.expectKey = false
			continue
		}
		top.expectKey = true
	}
}

// ParseLegacyHookSidecar reads the KEY=value hooks/.hookcfg that releases
// before 0.8.10 wrote. Every line is blank, a # comment, or [export ]KEY=value
// with a shell-name key, and every key is given once; ok is false for any
// other document (JSON, a byte-order mark or a comment in front of other
// text, a line that is not KEY=value, a key given twice), which is
// malformed state, never read for a value.
func ParseLegacyHookSidecar(data []byte) (values map[string]string, ok bool) {
	values = map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		key = strings.TrimSpace(key)
		if _, seen := values[key]; !found || !legacyHookSidecarKey(key) || seen {
			return nil, false
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return values, true
}

// legacyHookSidecarKey reports a shell variable name.
func legacyHookSidecarKey(key string) bool {
	if key == "" || (key[0] >= '0' && key[0] <= '9') {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// flatHookRecordValue reads one key of a hooks/.hookcfg.<connector> record as
// the shared Unix hooks do (defenseclaw_flat_hookcfg_value): KEY=value lines
// with an upper-case key, each key once, every line ended by a newline, no
// NUL byte. ok is false for any other record.
func flatHookRecordValue(data []byte, wanted string) (value string, ok bool) {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0 {
		return "", false
	}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		key, rest, found := strings.Cut(line, "=")
		if _, dup := seen[key]; !found || dup || !flatHookRecordKey(key) {
			return "", false
		}
		seen[key] = struct{}{}
		if key == wanted {
			value, ok = rest, true
		}
	}
	return value, ok
}

// flatHookRecordKey reports an upper-case shell variable name.
func flatHookRecordKey(key string) bool {
	if key == "" || (key[0] >= '0' && key[0] <= '9') {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
