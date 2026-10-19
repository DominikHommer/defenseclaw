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
	server := openCodeStubGateway(t, `{}`, `{"action":"block"}`)
	lines := runOpenCodePluginHarness(t, openCodePluginTestData(t, server), 2)
	if len(lines) < 2 || lines[0] == "allow" || lines[1] == "allow" {
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
	if err := writeHookScriptsCommonWithFailMode(dir, "127.0.0.1:1", "test-token", "closed", []string{"claude-code-hook.sh"}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(dir, "claude-code-hook.sh"))
	cmd.Env = append(os.Environ(), "DEFENSECLAW_HOME="+filepath.Join(t.TempDir(), "missing"))
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse"}`)
	output, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
		t.Fatalf("closed hook allowed missing home: err=%v output=%q", err, output)
	}
}
