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
	if err := writeHookScriptsCommonWithFailMode(dir, "127.0.0.1:1", "test-token", "closed", []string{"claude-code-hook.sh", "copilot-hook.sh", "hermes-hook.sh"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, payload, decision string
		args                    []string
	}{
		{"claude-code-hook.sh", `{"hook_event_name":"PreToolUse"}`, "", nil},
		{"copilot-hook.sh", `{}`, `"permissionDecision":"deny"`, []string{"--event", "preToolUse"}},
		{"hermes-hook.sh", `{"event":"pre_tool_call"}`, `"action":"block"`, nil},
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
