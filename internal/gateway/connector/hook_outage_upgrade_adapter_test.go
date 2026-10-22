package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefreshClosesReleasedWindowsCopilotAdapter(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "released-hooks", "1.0.3", "copilot-hook.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	fixture = []byte(strings.ReplaceAll(
		strings.ReplaceAll(string(fixture), "{{.HookBinaryPS}}", "C:\\Program Files\\DefenseClaw\\defenseclaw-hook.exe"),
		"{{.CopilotHookTimeoutMS}}", "25000",
	))
	for _, mode := range []string{"closed", "open"} {
		t.Run(mode, func(t *testing.T) {
			hookDir := t.TempDir()
			path := filepath.Join(hookDir, "copilot-hook.ps1")
			if err := os.WriteFile(path, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := RefreshHookFailModes(hookDir, func(name string) string {
				if name == "copilot" {
					return mode
				}
				return ""
			}); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "open" {
				if string(got) != string(fixture) {
					t.Fatal("the administrator's open adapter changed")
				}
			} else {
				for _, want := range []string{"$process.ExitCode -ne 0", "$failClosed", "permissionDecision", "25000",
					"C:\\Program Files\\DefenseClaw\\defenseclaw-hook.exe"} {
					if !strings.Contains(string(got), want) {
						t.Fatalf("refreshed adapter lacks %q", want)
					}
				}
			}
		})
	}
}

func TestRefreshClosesCurrentOpenWindowsCopilotAdapter(t *testing.T) {
	hookDir := t.TempDir()
	path := filepath.Join(hookDir, "copilot-hook.ps1")
	data := templateData{HookBinaryPS: `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`, CopilotHookTimeoutMS: 25000, FailMode: "open"}
	open, err := renderHookTemplate("copilot-hook.ps1", data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, open, 0o600); err != nil {
		t.Fatal(err)
	}
	refresh := func() (HookFailModeRefresh, error) {
		return RefreshHookFailModes(hookDir, func(string) string { return "closed" })
	}
	changed, err := refresh()
	if err != nil || len(changed.Scripts) != 1 {
		t.Fatalf("close current open adapter: %+v %v", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "$failClosed = 'true' -eq 'true'") {
		t.Fatal("adapter stayed open")
	}
	changed, err = refresh()
	if err != nil || len(changed.Scripts) != 0 {
		t.Fatalf("second refresh should be unchanged: %+v %v", changed, err)
	}
	if err := os.WriteFile(path, append(got, []byte("\n# unexpected edit\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := refresh(); err == nil || !strings.Contains(err.Error(), "unrecognized") {
		t.Fatalf("modified adapter must be refused: %v", err)
	}
}
