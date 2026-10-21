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

//go:build !windows

package image

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func newMockServer(t *testing.T) (*mockLLM, *httptest.Server) {
	t.Helper()
	m := newMockLLM(builtinMockScenarios...)
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return m, srv
}

func mockPost(t *testing.T, url, body string, headers map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// sseEvents parses an event stream into (event, data) pairs.
func sseEvents(t *testing.T, body string) [][2]string {
	t.Helper()
	var out [][2]string
	var name string
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data := strings.TrimPrefix(line, "data: ")
			if data != "[DONE]" && !json.Valid([]byte(data)) {
				t.Fatalf("event %s carries invalid JSON: %s", name, data)
			}
			out = append(out, [2]string{name, data})
		}
	}
	return out
}

// jsonHas reports whether some object in doc holds key: want, looking into
// string values that are JSON documents themselves (tool-call arguments).
func jsonHas(doc interface{}, key string, want interface{}) bool {
	switch v := doc.(type) {
	case map[string]interface{}:
		for k, child := range v {
			if (k == key && reflect.DeepEqual(child, want)) || jsonHas(child, key, want) {
				return true
			}
		}
	case []interface{}:
		for _, child := range v {
			if jsonHas(child, key, want) {
				return true
			}
		}
	case string:
		var inner interface{}
		if strings.HasPrefix(v, "{") && json.Unmarshal([]byte(v), &inner) == nil {
			return jsonHas(inner, key, want)
		}
	}
	return false
}

func quoteJSON(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

const (
	anthropicTools        = `"tools":[{"name":"Bash","input_schema":{}},{"name":"Read","input_schema":{}}]`
	hermesTerminalTool    = `{"type":"function","function":{"name":"terminal","parameters":{"type":"object","properties":{"command":{"type":"string"},"background":{"type":"boolean"}},"required":["command"]}}}`
	antigravityRunCommand = `{"functionDeclarations":[{"name":"view_file","parameters":{"type":"object"}},{"name":"run_command","parametersJsonSchema":{"type":"object","properties":{"CommandLine":{"type":"string"},"Cwd":{"type":"string"},"WaitMsBeforeAsync":{"type":"integer"}},"required":["CommandLine","Cwd","WaitMsBeforeAsync"]}}]}`
)

// TestMockLLMStreams checks the streamed shapes: Anthropic's event order and
// input_json_delta pieces, the Responses events with their sequence numbers,
// and the Chat Completions chunks, each carrying the scenario's tool call.
func TestMockLLMStreams(t *testing.T) {
	_, srv := newMockServer(t)
	allowCmd := "echo dc-hookfire-allowed > " + builtinAllowSideEffect
	stream := func(path, body string) [][2]string {
		t.Helper()
		code, out := mockPost(t, srv.URL+path, body, nil)
		if code != http.StatusOK {
			t.Fatalf("%s: status %d", path, code)
		}
		return sseEvents(t, out)
	}
	names := func(events [][2]string) string {
		var out []string
		for _, ev := range events {
			out = append(out, ev[0])
		}
		return strings.Join(out, ",")
	}

	events := stream("/v1/messages", `{"model":"claude-x","stream":true,"messages":[{"role":"user","content":`+quoteJSON(builtinAllowPrompt)+`}],`+anthropicTools+`}`)
	var partial strings.Builder
	for _, ev := range events {
		var data struct {
			Delta struct {
				Type        string `json:"type"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
		}
		_ = json.Unmarshal([]byte(ev[1]), &data)
		if data.Delta.Type == "input_json_delta" {
			partial.WriteString(data.Delta.PartialJSON)
		}
		if ev[0] == "message_delta" && data.Delta.StopReason != "tool_use" {
			t.Fatalf("message_delta = %s, want the tool_use stop reason", ev[1])
		}
	}
	if got := names(events); !strings.HasPrefix(got, "message_start,ping,content_block_start,content_block_delta") ||
		!strings.HasSuffix(got, "content_block_stop,message_delta,message_stop") {
		t.Fatalf("anthropic event order = %s", got)
	}
	var input map[string]string
	if err := json.Unmarshal([]byte(partial.String()), &input); err != nil || input["command"] != allowCmd {
		t.Fatalf("streamed tool input = %q (%v)", partial.String(), err)
	}

	events = stream("/v1/responses", `{"model":"mock-model","stream":true,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":`+
		quoteJSON(builtinBlockPrompt)+`}]}],"tools":[{"type":"function","name":"shell_command"}]}`)
	for i, ev := range events {
		var data struct {
			Type string `json:"type"`
			Seq  int    `json:"sequence_number"`
		}
		if err := json.Unmarshal([]byte(ev[1]), &data); err != nil || data.Type != ev[0] || data.Seq != i {
			t.Fatalf("responses event %d = %s %s", i, ev[0], ev[1])
		}
	}
	if got := names(events); got != "response.created,response.output_item.added,response.output_item.done,response.completed" || !strings.Contains(events[3][1], "echo BLOCKME") {
		t.Fatalf("responses events = %s, completed %s", got, events[len(events)-1][1])
	}
	// A text answer streams deltas.
	if got := names(stream("/v1/responses", `{"stream":true,"input":"hello"}`)); !strings.Contains(got, "response.output_text.delta") {
		t.Fatalf("text stream = %s", got)
	}

	events = stream("/v1/chat/completions", `{"stream":true,"messages":[{"role":"user","content":`+quoteJSON(builtinAllowPrompt)+`}],"tools":[`+hermesTerminalTool+`]}`)
	var name, arguments, finish string
	for _, ev := range events {
		if ev[1] == "[DONE]" {
			continue
		}
		var chunk struct {
			Object  string `json:"object"`
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(ev[1]), &chunk); err != nil || chunk.Object != "chat.completion.chunk" {
			t.Fatalf("chunk %s: %v", ev[1], err)
		}
		for _, call := range chunk.Choices[0].Delta.ToolCalls {
			name += call.Function.Name
			arguments += call.Function.Arguments
		}
		if chunk.Choices[0].FinishReason != nil {
			finish = *chunk.Choices[0].FinishReason
		}
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(arguments), &args); err != nil || name != "terminal" || finish != "tool_calls" ||
		args["command"] != allowCmd || events[len(events)-1][1] != "[DONE]" {
		t.Fatalf("streamed call %q %q finish %q: %v", name, arguments, finish, err)
	}
}

func TestMockLLMAuxiliaryRoutes(t *testing.T) {
	_, srv := newMockServer(t)
	for _, tc := range []struct {
		method, path string
		headers      map[string]string
		body         string
		code         int
		says         []string
	}{
		{http.MethodGet, "/v1/models", map[string]string{"anthropic-version": "2023-06-01"}, "", 200, []string{`"type":"model"`, `"has_more":false`}},
		{http.MethodGet, "/v1/models/claude-x", map[string]string{"x-api-key": "k"}, "", 200, []string{`"id":"claude-x"`}},
		{http.MethodGet, "/models", nil, "", 200, []string{`"object":"list"`, `"mock-model"`}},
		{http.MethodGet, "/v1/responses", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}, "", http.StatusUpgradeRequired, nil},
		{http.MethodPost, "/v1/messages/count_tokens", nil, `{"messages":[{"role":"user","content":"abcdefgh"}]}`, 200, []string{`"input_tokens"`}},
		{http.MethodPost, "/v1/messages", nil, `{not json`, http.StatusBadRequest, nil},
		{http.MethodPost, "/v1/embeddings", nil, `{}`, http.StatusNotFound, nil},
		{http.MethodHead, "/", nil, "", 200, nil},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.code {
			t.Fatalf("%s %s = %d %s", tc.method, tc.path, resp.StatusCode, raw)
		}
		for _, want := range tc.says {
			if !strings.Contains(string(raw), want) {
				t.Fatalf("%s %s = %s, want %s", tc.method, tc.path, raw, want)
			}
		}
	}
}
