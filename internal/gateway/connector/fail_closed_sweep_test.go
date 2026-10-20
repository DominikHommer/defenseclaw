package connector

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenCodeClosedPluginRejectsUnusableAnswers(t *testing.T) {
	server := openCodeStubGateway(t, `{}`, `{"action":"block"}`, `{"action":"confirm"}`)
	lines := runOpenCodePluginHarness(t, openCodePluginTestData(t, server), 3)
	if len(lines) < 3 || lines[0] == "allow" || lines[1] == "allow" || lines[2] == "allow" {
		t.Fatalf("closed plugin allowed unusable gateway answers: %q", lines)
	}
}

func TestOpenCodeExplicitPerUserOpenAllowsUnusableAnswer(t *testing.T) {
	server := openCodeStubGateway(t, `{}`, `{"action":"unknown"}`)
	data := openCodePluginTestData(t, server)
	data.FailMode = "open"
	lines := runOpenCodePluginHarness(t, data, 2)
	if len(lines) != 2 || lines[0] != "allow" || lines[1] != "allow" {
		t.Fatalf("explicit per-user open rejected unusable answers: %q", lines)
	}
}

func TestInspectShellActionMatrixWithAndWithoutJQ(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hooks")
	}
	noJQPath := t.TempDir()
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.Name() == "jq" || entry.IsDir() {
				continue
			}
			source := filepath.Join(dir, entry.Name())
			target := filepath.Join(noJQPath, entry.Name())
			if _, err := os.Lstat(target); err == nil {
				continue
			}
			_ = os.Symlink(source, target)
		}
	}
	for _, parser := range []struct {
		name, path string
	}{
		{"jq available", os.Getenv("PATH")},
		{"jq absent", noJQPath},
	} {
		if parser.name == "jq available" {
			if _, err := exec.LookPath("jq"); err != nil {
				continue
			}
		}
		for _, verdict := range []struct {
			name, body string
			exitCode   int
		}{
			{"allow", `{"action":"allow"}`, 0},
			{"block", `{"action":"block"}`, 2},
			{"missing", `{}`, 2},
			{"unknown", `{"action":"unrecognized"}`, 2},
			{"non-string", `{"action":42}`, 2},
		} {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, verdict.body)
			}))
			dir := t.TempDir()
			if err := writeHookScriptsCommonWithFailMode(dir, strings.TrimPrefix(server.URL, "http://"), "test-token", "closed", nil); err != nil {
				server.Close()
				t.Fatal(err)
			}
			bakeHookPathForTest(t, filepath.Join(dir, "inspect-request.sh"), parser.path)
			for _, name := range []string{"inspect-request.sh", "inspect-tool.sh", "inspect-response.sh", "inspect-tool-response.sh"} {
				t.Run(parser.name+"/"+verdict.name+"/"+name, func(t *testing.T) {
					cmd := exec.Command("bash", filepath.Join(dir, name))
					cmd.Env = append(os.Environ(), "PATH="+parser.path, "DEFENSECLAW_HOME="+t.TempDir(), "DEFENSECLAW_FAIL_MODE=closed")
					cmd.Stdin = strings.NewReader(`{"tool":"Bash","input":"echo marker","content":"marker"}`)
					output, err := cmd.CombinedOutput()
					got := 0
					if err != nil {
						exit, ok := err.(*exec.ExitError)
						if !ok {
							t.Fatalf("run hook: %v, output=%q", err, output)
						}
						got = exit.ExitCode()
					}
					if got != verdict.exitCode {
						t.Fatalf("hook exit=%d, want=%d, output=%q", got, verdict.exitCode, output)
					}
				})
			}
			server.Close()
		}
	}
}

func TestInspectShellClosedRejectsMissingAndUnknownActions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hooks")
	}
	for _, body := range []string{`{}`, `{"action":"unrecognized"}`, `{"action":42}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}))
		for _, name := range []string{"inspect-request.sh", "inspect-tool.sh", "inspect-response.sh", "inspect-tool-response.sh"} {
			t.Run(name+"/"+body, func(t *testing.T) {
				dir := t.TempDir()
				if err := writeHookScriptsCommonWithFailMode(dir, strings.TrimPrefix(server.URL, "http://"), "test-token", "closed", nil); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("bash", filepath.Join(dir, name))
				cmd.Env = append(os.Environ(), "DEFENSECLAW_HOME="+t.TempDir(), "DEFENSECLAW_FAIL_MODE=closed")
				cmd.Stdin = strings.NewReader(`{"tool":"Bash","input":"echo marker","content":"marker"}`)
				output, err := cmd.CombinedOutput()
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
					t.Fatalf("unusable action did not fail closed: err=%v output=%q", err, output)
				}
			})
		}
		server.Close()
	}
}

func TestClosedShellHookRejectsMissingHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hooks")
	}
	dir := t.TempDir()
	if err := writeHookScriptsCommonWithFailMode(dir, "127.0.0.1:1", "test-token", "closed", []string{"claude-code-hook.sh", "copilot-hook.sh", "hermes-hook.sh", "antigravity-hook.sh"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, payload, decision string
		args                    []string
	}{
		{"claude-code-hook.sh", `{"hook_event_name":"PreToolUse"}`, "", nil},
		{"copilot-hook.sh", `{}`, `"permissionDecision":"deny"`, []string{"--event", "preToolUse"}},
		{"hermes-hook.sh", `{"event":"pre_tool_call"}`, `"action":"block"`, nil},
		{"antigravity-hook.sh", `{}`, `"decision":"deny"`, []string{"PreToolUse"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", append([]string{filepath.Join(dir, tc.name)}, tc.args...)...)
			cmd.Env = append(os.Environ(), "DEFENSECLAW_HOME="+filepath.Join(t.TempDir(), "missing"))
			cmd.Stdin = strings.NewReader(tc.payload)
			output, err := cmd.CombinedOutput()
			if tc.decision != "" {
				if err != nil || !strings.Contains(string(output), tc.decision) {
					t.Fatalf("closed hook did not emit native denial: err=%v output=%q", err, output)
				}
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
				t.Fatalf("closed hook allowed missing home: err=%v output=%q", err, output)
			}
		})
	}
}
