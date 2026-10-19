// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const nativeAnthropicInspectionLimit = 256 << 10

// nativeAnthropicInspection projects every provider-visible text field in the
// accepted Messages subset into one bounded, role-labelled inspection input.
// The shared proxy passes that same projection to text and message-aware
// inspectors. Opaque media, server tools and unknown fields refuse admission.
// The original body remains untouched for the provider.
func nativeAnthropicInspection(body []byte) (string, error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil || !nativeAnthropicKeys(top, "model", "max_tokens", "messages", "stream", "system", "tools", "tool_choice") {
		return "", errNativeModelAdapter
	}
	var projection []string
	if raw, ok := top["system"]; ok {
		visible, err := nativeAnthropicText(raw)
		if err != nil || strings.TrimSpace(visible) == "" {
			return "", errNativeModelAdapter
		}
		projection = append(projection, "system:\n"+visible)
	}
	if raw, ok := top["tools"]; ok {
		visible, err := nativeAnthropicTools(raw)
		if err != nil {
			return "", errNativeModelAdapter
		}
		projection = append(projection, "client tools:\n"+visible)
	}
	if raw, ok := top["tool_choice"]; ok && !nativeAnthropicAutoToolChoice(raw) {
		return "", errNativeModelAdapter
	}
	var rawMessages []map[string]json.RawMessage
	if json.Unmarshal(top["messages"], &rawMessages) != nil || len(rawMessages) == 0 || len(rawMessages) > 64 {
		return "", errNativeModelAdapter
	}
	lastUserVisible := ""
	for index, rawMessage := range rawMessages {
		if !nativeAnthropicKeys(rawMessage, "role", "content") || len(rawMessage) != 2 {
			return "", errNativeModelAdapter
		}
		var role string
		if json.Unmarshal(rawMessage["role"], &role) != nil || (role != "user" && role != "assistant") {
			return "", errNativeModelAdapter
		}
		visible, err := nativeAnthropicMessageContent(role, rawMessage["content"])
		if err != nil {
			return "", err
		}
		projection = append(projection, fmt.Sprintf("message %d %s:\n%s", index, role, visible))
		if index == len(rawMessages)-1 && role == "user" {
			lastUserVisible = visible
		}
	}
	if strings.TrimSpace(lastUserVisible) == "" {
		return "", errNativeModelAdapter
	}
	visible := strings.Join(projection, "\n")
	if len(visible) > nativeAnthropicInspectionLimit {
		return "", errNativeModelAdapter
	}
	return visible, nil
}

func nativeAnthropicKeys(values map[string]json.RawMessage, allowed ...string) bool {
	if values == nil {
		return false
	}
	for key := range values {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func nativeAnthropicText(raw json.RawMessage) (string, error) {
	var value string
	if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &value) == nil {
		return value, nil
	}
	if len(raw) == 0 || raw[0] != '[' {
		return "", errNativeModelAdapter
	}
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil || len(blocks) == 0 {
		return "", errNativeModelAdapter
	}
	parts := make([]string, 0, len(blocks))
	for _, block := range blocks {
		if !nativeAnthropicKeys(block, "type", "text", "cache_control") || !nativeAnthropicBlockType(block, "text") ||
			!nativeAnthropicCache(block["cache_control"]) {
			return "", errNativeModelAdapter
		}
		var text string
		if json.Unmarshal(block["text"], &text) != nil {
			return "", errNativeModelAdapter
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, "\n"), nil
}

func nativeAnthropicMessageContent(role string, raw json.RawMessage) (string, error) {
	var visible string
	if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &visible) == nil {
		return visible, nil
	}
	if len(raw) == 0 || raw[0] != '[' {
		return "", errNativeModelAdapter
	}
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil || len(blocks) == 0 {
		return "", errNativeModelAdapter
	}
	var parts []string
	for _, block := range blocks {
		var kind string
		if json.Unmarshal(block["type"], &kind) != nil {
			return "", errNativeModelAdapter
		}
		switch kind {
		case "text":
			encoded, marshalErr := json.Marshal([]map[string]json.RawMessage{block})
			if marshalErr != nil {
				return "", errNativeModelAdapter
			}
			text, textErr := nativeAnthropicText(encoded)
			if textErr != nil {
				return "", textErr
			}
			parts = append(parts, text)
		case "tool_result":
			if role != "user" || !nativeAnthropicKeys(block, "type", "tool_use_id", "content", "is_error", "cache_control") ||
				!nativeAnthropicCache(block["cache_control"]) || !nativeAnthropicID(block["tool_use_id"]) {
				return "", errNativeModelAdapter
			}
			if rawError, ok := block["is_error"]; ok {
				var isError bool
				if json.Unmarshal(rawError, &isError) != nil {
					return "", errNativeModelAdapter
				}
			}
			text := ""
			if content, ok := block["content"]; ok {
				var textErr error
				text, textErr = nativeAnthropicText(content)
				if textErr != nil {
					return "", textErr
				}
			}
			parts = append(parts, "tool result "+string(block["tool_use_id"])+":\n"+text)
		case "tool_use":
			if role != "assistant" || !nativeAnthropicKeys(block, "type", "id", "name", "input", "cache_control") ||
				!nativeAnthropicCache(block["cache_control"]) || !nativeAnthropicID(block["id"]) {
				return "", errNativeModelAdapter
			}
			var name string
			if json.Unmarshal(block["name"], &name) != nil || strings.TrimSpace(name) == "" || len(name) > 128 {
				return "", errNativeModelAdapter
			}
			input, inputErr := nativeAnthropicCanonicalObject(block["input"])
			if inputErr != nil {
				return "", inputErr
			}
			parts = append(parts, "tool use "+name+" "+string(block["id"])+":\n"+input)
		default:
			return "", errNativeModelAdapter
		}
	}
	return strings.Join(parts, "\n"), nil
}

func nativeAnthropicBlockType(block map[string]json.RawMessage, want string) bool {
	var kind string
	return json.Unmarshal(block["type"], &kind) == nil && kind == want
}

func nativeAnthropicID(raw json.RawMessage) bool {
	var id string
	return json.Unmarshal(raw, &id) == nil && id != "" && len(id) <= 128 && !strings.ContainsAny(id, "\x00\r\n")
}

func nativeAnthropicCache(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var cache map[string]json.RawMessage
	if json.Unmarshal(raw, &cache) != nil || !nativeAnthropicKeys(cache, "type", "ttl") {
		return false
	}
	var kind string
	if json.Unmarshal(cache["type"], &kind) != nil || kind != "ephemeral" {
		return false
	}
	if ttl, ok := cache["ttl"]; ok {
		var value string
		return json.Unmarshal(ttl, &value) == nil && (value == "5m" || value == "1h")
	}
	return true
}

func nativeAnthropicAutoToolChoice(raw json.RawMessage) bool {
	var choice map[string]json.RawMessage
	if json.Unmarshal(raw, &choice) != nil || len(choice) != 1 || !nativeAnthropicKeys(choice, "type") {
		return false
	}
	var kind string
	return json.Unmarshal(choice["type"], &kind) == nil && kind == "auto"
}

func nativeAnthropicTools(raw json.RawMessage) (string, error) {
	var tools []map[string]json.RawMessage
	if json.Unmarshal(raw, &tools) != nil || len(tools) == 0 || len(tools) > 128 {
		return "", errNativeModelAdapter
	}
	var descriptions []string
	for _, tool := range tools {
		if !nativeAnthropicKeys(tool, "name", "description", "input_schema", "cache_control") ||
			!nativeAnthropicCache(tool["cache_control"]) {
			return "", errNativeModelAdapter
		}
		var name, description string
		if json.Unmarshal(tool["name"], &name) != nil || name == "" || len(name) > 128 ||
			json.Unmarshal(tool["description"], &description) != nil || description == "" {
			return "", errNativeModelAdapter
		}
		schema, err := nativeAnthropicCanonicalObject(tool["input_schema"])
		if err != nil {
			return "", err
		}
		descriptions = append(descriptions, name+"\n"+description+"\n"+schema)
	}
	return strings.Join(descriptions, "\n"), nil
}

func nativeAnthropicCanonicalObject(raw json.RawMessage) (string, error) {
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&object) != nil || object == nil {
		return "", errNativeModelAdapter
	}
	// JSON re-encoding escapes HTML characters and can hide the actual text
	// seen by a model. Project decoded keys and strings verbatim, in stable
	// order, so scanners see every provider-visible word.
	var projected strings.Builder
	if !nativeAnthropicObjectText(&projected, object, 0) {
		return "", errNativeModelAdapter
	}
	return projected.String(), nil
}

func nativeAnthropicObjectText(out *strings.Builder, value any, depth int) bool {
	if depth > 64 || out.Len() > nativeAnthropicInspectionLimit {
		return false
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			out.WriteString(key)
			out.WriteString(": ")
			if !nativeAnthropicObjectText(out, typed[key], depth+1) {
				return false
			}
			out.WriteByte('\n')
		}
	case []any:
		for _, item := range typed {
			if !nativeAnthropicObjectText(out, item, depth+1) {
				return false
			}
			out.WriteByte('\n')
		}
	case string:
		out.WriteString(typed)
	case json.Number:
		out.WriteString(typed.String())
	case bool:
		out.WriteString(fmt.Sprint(typed))
	case nil:
		out.WriteString("null")
	default:
		return false
	}
	return out.Len() <= nativeAnthropicInspectionLimit
}
