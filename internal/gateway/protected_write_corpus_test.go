// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

type protectedCorpusFixture struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Target  string `json:"target"`
	Content string `json:"content"`
}

type protectedCorpusRow struct {
	ID         string                   `json:"id"`
	Class      string                   `json:"class"`
	Command    string                   `json:"command"`
	Dialect    string                   `json:"dialect"`
	Tool       string                   `json:"tool"`
	CWD        string                   `json:"cwd"`
	Fixture    []protectedCorpusFixture `json:"fixture"`
	Expected   string                   `json:"expected"`
	Connectors []string                 `json:"connectors"`
	Modes      []string                 `json:"modes"`
	OS         []string                 `json:"os"`
}

func readProtectedCorpus(t *testing.T) []protectedCorpusRow {
	t.Helper()
	var rows []protectedCorpusRow
	for _, name := range []string{"allow", "block"} {
		path := filepath.Join("..", "hookpaths", "testdata", "protected_write_"+name+".jsonl")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			var row protectedCorpusRow
			if err := json.Unmarshal(line, &row); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			if row.ID == "" || row.Expected != name || len(row.Connectors) == 0 || len(row.Modes) == 0 || len(row.OS) == 0 {
				t.Fatalf("%s: incomplete row %s", path, row.ID)
			}
			rows = append(rows, row)
		}
	}
	return rows
}

func prepareProtectedCorpus(t *testing.T, home string, rows []protectedCorpusRow) {
	t.Helper()
	made := make(map[string]protectedCorpusFixture)
	for _, row := range rows {
		for _, fixture := range row.Fixture {
			if fixture.Path == "" || filepath.IsAbs(fixture.Path) || strings.HasPrefix(filepath.Clean(fixture.Path), "..") {
				t.Fatalf("%s: invalid fixture path", row.ID)
			}
			path := filepath.Join(home, fixture.Path)
			if prior, exists := made[path]; exists {
				if prior != fixture {
					t.Fatalf("%s: conflicting fixture %s", row.ID, fixture.Path)
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			var err error
			switch fixture.Type {
			case "dir":
				err = os.MkdirAll(path, 0700)
			case "file":
				content := fixture.Content
				if content == "" {
					content = "dccert-block-marker\n"
				}
				err = os.WriteFile(path, []byte(content), 0600)
			case "symlink", "symlink_raw", "hardlink":
				target := fixture.Target
				if fixture.Type != "symlink_raw" && !filepath.IsAbs(target) {
					target = filepath.Join(home, target)
				}
				if fixture.Type == "hardlink" {
					err = os.Link(target, path)
				} else {
					err = os.Symlink(target, path)
				}
			default:
				t.Fatalf("%s: unknown fixture type %s", row.ID, fixture.Type)
			}
			if err != nil {
				t.Fatalf("%s: fixture %s: %v", row.ID, fixture.Path, err)
			}
			made[path] = fixture
		}
	}
}

func protectedCorpusToolInput(row protectedCorpusRow, home string) map[string]any {
	switch strings.ToLower(row.Tool) {
	case "write":
		return map[string]any{"file_path": filepath.Join(home, row.Command), "content": "dccert-block-marker\n"}
	case "edit":
		return map[string]any{"file_path": filepath.Join(home, row.Command), "old_string": "old", "new_string": "dccert-block-marker"}
	case "apply_patch":
		return map[string]any{"command": row.Command}
	default:
		return map[string]any{"command": row.Command, "description": "Protected file check"}
	}
}

func decideProtectedCorpus(row protectedCorpusRow, home, connector, mode, osName string) (string, error) {
	if osName == "windows" {
		args, _ := json.Marshal(map[string]string{"command": row.Command})
		winHome := `C:\Users\b00`
		input := actionfacts.Input{Tool: row.Tool, Args: args, CWD: winHome + `\proj`, ActiveHome: winHome}
		switch row.Dialect {
		case "powershell":
			input.DialectHint = actionfacts.DialectPowerShell
		case "cmd":
			input.DialectHint = actionfacts.DialectCMD
		default:
			input.DialectHint = actionfacts.DialectPOSIX
		}
		if row.Dialect != "cmd" {
			input.DialectHint = agentHookWindowsShellDialect(input)
		}
		findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
			Input: input, LegacyText: string(args), Connector: connector,
			EnforcementCapable: true, ProtectedHomeHook: mode == "managed",
		})
		return string(buildVerdict(findings, "tool_call").Action), nil
	}
	body, err := json.Marshal(map[string]any{
		"session_id":      "corpus-" + row.ID + "-" + osName + "-" + mode,
		"hook_event_name": "PreToolUse", "tool_name": row.Tool,
		"cwd": filepath.Join(home, row.CWD), "tool_input": protectedCorpusToolInput(row, home),
	})
	if err != nil {
		return "", err
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", bytes.NewReader(body))
	if mode == "managed" {
		header := hookpaths.Resolve(body)
		if header != "" {
			if _, ok := hookpaths.Decode(header); !ok {
				return "", fmt.Errorf("invalid resolved writes header")
			}
			req.Header.Set(hookpaths.Header, header)
		}
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	res := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(res, req)
	var verdict struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &verdict); err != nil {
		return "", fmt.Errorf("HTTP %d: %w", res.Code, err)
	}
	if verdict.Action != "allow" && verdict.Action != "block" {
		return "", fmt.Errorf("HTTP %d: unknown action", res.Code)
	}
	return verdict.Action, nil
}

func TestProtectedWriteCorpus(t *testing.T) {
	started := time.Now()
	rows := readProtectedCorpus(t)
	for _, connector := range []string{"claudecode", "codex"} {
		installToolCallCorpusProfileConnector(t, connector, "default")
	}
	home := t.TempDir()
	oldHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", home); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Setenv("HOME", oldHome) })
	prepareProtectedCorpus(t, home, rows)

	type result struct {
		id, connector, mode, osName, expected, actual string
		err                                           error
	}
	jobs := make(chan protectedCorpusRow)
	results := make(chan result, len(rows)*8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for row := range jobs {
				for _, osName := range row.OS {
					for _, connector := range row.Connectors {
						for _, mode := range row.Modes {
							actual, err := decideProtectedCorpus(row, home, connector, mode, osName)
							results <- result{row.ID, connector, mode, osName, row.Expected, actual, err}
						}
					}
				}
			}
		}()
	}
	for _, row := range rows {
		jobs <- row
	}
	close(jobs)
	workers.Wait()
	close(results)
	var allowed, blocked int
	for cell := range results {
		if cell.err != nil || cell.actual != cell.expected {
			t.Errorf("%s %s/%s/%s: expected %s, got %s (%v)", cell.id, cell.connector, cell.mode, cell.osName, cell.expected, cell.actual, cell.err)
		}
		if cell.expected == "allow" {
			allowed++
		} else {
			blocked++
		}
	}
	t.Logf("%d rows, %d allow cells, %d block cells in %s", len(rows), allowed, blocked, time.Since(started))
}
