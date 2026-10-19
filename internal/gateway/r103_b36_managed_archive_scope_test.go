package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestR103B36ManagedArchiveScopeUsesClientWalk replays the GAP-0278 FP-0001
// PreToolUse payload from the managed RHEL lane. The hook client runs as the
// user and walks the operands; the managed gateway runs with ProtectHome and
// cannot search the user's home, so its own walk is incomplete. The ordinary
// project write must be allowed from the client's opaque-scope fact, while
// writes inside the extraction scope, through a link into it, without a fact,
// and the lane's protected-file decoys stay denied.
func TestR103B36ManagedArchiveScopeUsesClientWalk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX managed hook evidence")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 directory")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "home")
	home := filepath.Join(homes, "dcad-r103-eng1@dclab.test")
	project := filepath.Join(home, "r103-t8a-b36-proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "build"), filepath.Join(project, "unpack")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for path, data := range map[string]string{keys: "# decoy\n", filepath.Join(project, "pkg.tgz"): "x", filepath.Join(project, "keys.tar"): "x"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("unpack/n", filepath.Join(project, "outlink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	const block, allow = `{"action":"block"`, `{"action":"allow"`
	post := func(t *testing.T, connector, command string, edit func(map[string]string)) string {
		t.Helper()
		if err := os.Chmod(homes, 0o700); err != nil {
			t.Fatal(err)
		}
		body := mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": project,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_fp",
			"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}})
		header := hookpaths.Resolve(body)
		if edit != nil {
			targets, ok := hookpaths.Decode(header)
			if !ok {
				t.Fatal("client header does not decode")
			}
			edit(targets)
			header = encodeTargets(t, targets)
		}
		// The managed gateway's view: ProtectHome hides the user's home.
		if err := os.Chmod(homes, 0); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = connector
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
		req.Header.Set(hookpaths.Header, header)
		if connector == "codex" {
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
		}
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
		recorder := httptest.NewRecorder()
		api.handleAgentHook(connector).ServeHTTP(recorder, req)
		return recorder.Body.String()
	}
	allowed := []string{
		"tar -xzf pkg.tgz --strip-components=1 -C build; echo hi > report.txt", // FP-0001
		"tar -xzf pkg.tgz --exclude=docs -C build; echo hi > report.txt",       // FP-0002
		"tar -C unpack -xf keys.tar; echo hi > report.txt",
	}
	blocked := []string{
		"tar -C unpack -xf keys.tar && echo k >> unpack/n1.txt",
		"tar xzf pkg.tgz && ./configure > build.log",
		"tar -C unpack -xf keys.tar && echo k >> outlink",
		`read X <<< "--target-directory=$HOME/.ssh"; printf marker > authorized_keys; cp "$X" authorized_keys`, // FG3-CP-B001
	}
	if runtime.GOOS == "linux" {
		blocked = append(blocked, "printf marker >> /proc/self/cwd/../.ssh/authorized_keys") // A1-0238
	}
	report := filepath.Join(project, "report.txt")
	inScope := filepath.Join(project, "unpack", "n1.txt")
	for _, connector := range []string{"claudecode", "codex"} {
		t.Run(connector, func(t *testing.T) {
			for _, command := range allowed {
				if got := post(t, connector, command, nil); !strings.HasPrefix(got, allow) {
					t.Errorf("%s = %.300s, want allow", command, got)
				}
			}
			for _, command := range blocked {
				if got := post(t, connector, command, nil); !strings.HasPrefix(got, block) {
					t.Errorf("%s = %.300s, want block", command, got)
				}
			}
			// An older client sends no fact: the operand stays unknown.
			if got := post(t, connector, allowed[0], func(targets map[string]string) {
				delete(targets, hookpaths.OpaqueScopeFactPrefix+report)
			}); !strings.HasPrefix(got, block) {
				t.Errorf("missing opaque-scope fact = %.300s, want block", got)
			}
			// A fact cannot clear a name inside the extraction scope.
			if got := post(t, connector, "tar -C unpack -xf keys.tar && echo k >> unpack/n1.txt", func(targets map[string]string) {
				targets[hookpaths.OpaqueScopeFactPrefix+inScope] = "0"
			}); !strings.HasPrefix(got, block) {
				t.Errorf("in-scope fact = %.300s, want block", got)
			}
		})
	}
	if _, ok := hookpaths.Decode(encodeTargets(t, map[string]string{hookpaths.OpaqueScopeFactPrefix + report: "1"})); ok {
		t.Fatal("decode accepted an opaque-scope value outside 0 and c")
	}
}
