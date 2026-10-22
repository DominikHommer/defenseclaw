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

//go:build windows

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const cursorAdapterHelperMode = "TEST_CURSOR_ADAPTER_MODE"
const cursorAdapterPIDFileEnv = "TEST_CURSOR_ADAPTER_PID_FILE"
const copilotAdapterHelperMode = "TEST_COPILOT_ADAPTER_MODE"
const copilotAdapterPIDFileEnv = "TEST_COPILOT_ADAPTER_PID_FILE"
const copilotAdapterChildStdoutEnv = "TEST_COPILOT_ADAPTER_CHILD_STDOUT"
const copilotAdapterChildStdoutFileEnv = "TEST_COPILOT_ADAPTER_CHILD_STDOUT_FILE"

func TestMain(m *testing.M) {
	switch os.Getenv(copilotAdapterHelperMode) {
	case "result":
		payload, err := io.ReadAll(os.Stdin)
		if err != nil || string(payload) != `{"source":"copilot-adapter-probe"}` {
			fmt.Fprintf(os.Stderr, "Copilot adapter helper received wrong stdin: %q\n", string(payload))
			os.Exit(6)
		}
		if strings.Join(os.Args[1:], "|") != "hook|--connector|copilot|--event|preToolUse" {
			fmt.Fprintln(os.Stderr, "Copilot adapter helper received unexpected arguments")
			os.Exit(5)
		}
		fmt.Print(`{"permissionDecision":"deny","permissionDecisionReason":"matched: test"}`)
		os.Exit(0)
	case "timeout":
		writeAdapterLauncherRecord(os.Getenv(copilotAdapterPIDFileEnv))
		// Outlive the contract so a launcher the adapter failed to kill cannot
		// end inside the deadline on its own.
		time.Sleep(2 * time.Duration(copilotWindowsHookContractTimeoutMS) * time.Millisecond)
		os.Exit(0)
	case "crash":
		os.Exit(7)
	case "crash-with-output":
		_, _ = io.Copy(io.Discard, os.Stdin)
		if path := os.Getenv(copilotAdapterChildStdoutFileEnv); path != "" {
			body, err := os.ReadFile(path)
			if err != nil {
				os.Exit(6)
			}
			_, _ = os.Stdout.Write(body)
		} else {
			fmt.Print(os.Getenv(copilotAdapterChildStdoutEnv))
		}
		os.Exit(7)
	}
	switch os.Getenv(cursorAdapterHelperMode) {
	case "success":
		payload, err := io.ReadAll(os.Stdin)
		if err != nil || !bytes.Contains(payload, []byte("cursor-adapter-probe")) {
			fmt.Fprintln(os.Stderr, "adapter helper did not receive the expected stdin payload")
			os.Exit(3)
		}
		if strings.Join(os.Args[1:], "|") != "hook|--connector|cursor|--enterprise-managed" {
			fmt.Fprintln(os.Stderr, "adapter helper received unexpected arguments")
			os.Exit(4)
		}
		fmt.Print(`{"continue":true}`)
		os.Exit(0)
	case "block":
		_, _ = io.Copy(io.Discard, os.Stdin)
		fmt.Print(`{"continue":false,"permission":"deny"}`)
		os.Exit(2)
	case "timeout":
		writeAdapterLauncherRecord(os.Getenv(cursorAdapterPIDFileEnv))
		// Outlive the contract, as the Copilot helper does.
		time.Sleep(2 * time.Duration(cursorWindowsHookContractTimeoutMS) * time.Millisecond)
		os.Exit(0)
	default:
		// Pre-existing connector fixtures exercise config, trust, CAS, and
		// teardown behavior without provisioning a real Codex installation.
		// Dedicated production-path tests explicitly restore the native policy
		// inspector; external CLI/gateway/installer tests use protected evidence.
		codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
			return codexEffectivePolicy{Source: "connector unit-test policy fixture"}, nil
		}
		os.Exit(m.Run())
	}
}

// writeAdapterLauncherRecord records the helper launcher's PID and kernel
// creation time. Adapter budgets are measured from the moment the launcher
// exists: PowerShell's own startup is host-dependent and outside them.
func writeAdapterLauncherRecord(pidFile string) {
	if pidFile == "" {
		return
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		fmt.Fprintf(os.Stderr, "adapter helper could not read its creation time: %v\n", err)
		os.Exit(7)
	}
	_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d %d", os.Getpid(), creation.Nanoseconds())), 0o600)
}

func readAdapterLauncherRecord(t *testing.T, pidFile, stderr string) (uint32, time.Time) {
	t.Helper()
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read helper PID: %v; stderr=%q", err, stderr)
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		t.Fatalf("helper record = %q, want PID and creation time", raw)
	}
	pid, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		t.Fatalf("parse helper PID: %v", err)
	}
	launchedNS, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		t.Fatalf("parse helper creation time: %v", err)
	}
	return uint32(pid), time.Unix(0, launchedNS)
}

func renderCopilotAdapterForTest(t *testing.T, hookPath string, timeoutMS int, failMode ...string) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/copilot-hook.ps1")
	if err != nil {
		t.Fatalf("read Copilot adapter: %v", err)
	}
	mode := "closed"
	if len(failMode) > 0 {
		mode = failMode[0]
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		HookBinaryPS:         strings.ReplaceAll(hookPath, "'", "''"),
		CopilotHookTimeoutMS: timeoutMS,
		FailMode:             mode,
	})
	if err != nil {
		t.Fatalf("render Copilot adapter: %v", err)
	}
	path := filepath.Join(t.TempDir(), "copilot-hook.ps1")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatalf("write Copilot adapter: %v", err)
	}
	return path
}

func runCopilotAdapterTest(
	t *testing.T,
	adapterPath string,
	payload string,
) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runCopilotAdapterEventTest(t, adapterPath, payload, "preToolUse")
}

func runCopilotAdapterEventTest(
	t *testing.T,
	adapterPath string,
	payload string,
	event string,
) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runCopilotAdapterEventEnvTest(t, adapterPath, payload, event, nil)
}

// runCopilotAdapterEventEnvTest adds env to the adapter's environment, so
// parallel subtests can give their own launcher helper settings.
func runCopilotAdapterEventEnvTest(
	t *testing.T,
	adapterPath string,
	payload string,
	event string,
	env []string,
) (stdout, stderr string, exitCode int) {
	t.Helper()
	quoted := strings.ReplaceAll(adapterPath, "'", "''")
	cmd := exec.Command(
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"& '"+quoted+"' -Event '"+event+"'",
	)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stdin = strings.NewReader(payload)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err == nil {
		return out.String(), errOut.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run Copilot adapter: %v", err)
	}
	return out.String(), errOut.String(), exitErr.ExitCode()
}

func TestCopilotAdapterPreservesJSONInputAndDenyResponse(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(copilotAdapterHelperMode, "result")
	adapter := renderCopilotAdapterForTest(t, executable, 10_000)
	stdout, stderr, code := runCopilotAdapterTest(
		t, adapter, `{"source":"copilot-adapter-probe"}`,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if strings.TrimSpace(stdout) != `{"permissionDecision":"deny","permissionDecisionReason":"matched: test"}` {
		t.Fatalf("stdout = %q, want exact Copilot deny JSON; stderr=%q", stdout, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestCopilotAdapterFailureAnswersWithNativeDenial(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCopilotAdapterForTest(t, missingHook, 10_000)
	stdout, stderr, code := runCopilotAdapterTest(
		t, adapter, `{"source":"copilot-adapter-probe"}`,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want native denial exit 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %q, want a native denial", stdout)
	}
	if !strings.Contains(stderr, "Copilot hook adapter failed closed") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
}

func TestCopilotAdapterCrashingChildFailsClosed(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(copilotAdapterHelperMode, "crash")
	adapter := renderCopilotAdapterForTest(t, executable, 10_000)
	stdout, stderr, code := runCopilotAdapterTest(t, adapter, `{"source":"copilot-adapter-probe"}`)
	if code != 0 || !strings.Contains(stdout, `"permissionDecision":"deny"`) ||
		!strings.Contains(stderr, "exited with status 7") {
		t.Fatalf("crashed child: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRefreshedReleasedCopilotAdapterCrashingChildFailsClosed(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("testdata", "released-hooks", "1.0.3", "copilot-hook.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(fixture), "{{.HookBinaryPS}}", strings.ReplaceAll(executable, "'", "''"))
	text = strings.ReplaceAll(text, "{{.CopilotHookTimeoutMS}}", "10000")
	adapter := filepath.Join(t.TempDir(), "copilot-hook.ps1")
	if err := os.WriteFile(adapter, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := closeReleasedCopilotAdapter(adapter); err != nil || !changed {
		t.Fatalf("refresh released Copilot adapter: changed=%v error=%v", changed, err)
	}
	t.Setenv(copilotAdapterHelperMode, "crash")
	stdout, stderr, code := runCopilotAdapterTest(t, adapter, `{"source":"copilot-adapter-probe"}`)
	if code != 0 || !strings.Contains(stdout, `"permissionDecision":"deny"`) ||
		!strings.Contains(stderr, "exited with status 7") {
		t.Fatalf("refreshed adapter after crashed child: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCopilotAdapterExplicitOpenKeepsOpenAnswer(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCopilotAdapterForTest(t, missingHook, 10_000, "open")
	stdout, stderr, code := runCopilotAdapterTest(t, adapter, `{}`)
	if code != 0 || stdout != "" || !strings.Contains(stderr, "failed open") {
		t.Fatalf("explicit open: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// TestCopilotAdapterKeepsChildDenialWhenChildExitsNonzero: a launcher that
// printed one complete denial for its event and then exited nonzero has
// decided, in either fail mode; anything else with a nonzero status is a
// failure the fail mode answers. "Denial" means what Copilot's JSON.parse
// reads: the exact top-level key (keys that differ only by case are other
// keys), the last duplicate wins, the value is the string "deny", any
// nesting depth. The adapter answers with its own denial, so the expected
// output is decoded and compared key by key.
func TestCopilotAdapterKeepsChildDenialWhenChildExitsNonzero(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	released, err := os.ReadFile(filepath.Join("testdata", "released-hooks", "1.0.3", "copilot-hook.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	refreshed := filepath.Join(t.TempDir(), "copilot-hook.ps1")
	text := strings.ReplaceAll(string(released), "{{.HookBinaryPS}}", strings.ReplaceAll(executable, "'", "''"))
	if err := os.WriteFile(refreshed, []byte(strings.ReplaceAll(text, "{{.CopilotHookTimeoutMS}}", "20000")), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := closeReleasedCopilotAdapter(refreshed); err != nil || !changed {
		t.Fatalf("refresh released Copilot adapter: changed=%v error=%v", changed, err)
	}
	adapters := map[string]string{
		"closed":            renderCopilotAdapterForTest(t, executable, 20_000, "closed"),
		"open":              renderCopilotAdapterForTest(t, executable, 20_000, "open"),
		"refreshed release": refreshed,
		// The budget cases need the check to outlast the hook budget.
		"closed budget": renderCopilotAdapterForTest(t, executable, 8_000, "closed"),
		"open budget":   renderCopilotAdapterForTest(t, executable, 8_000, "open"),
	}
	// Millions of tokens: PowerShell cannot check this inside the budget.
	huge := filepath.Join(t.TempDir(), "huge-answer.json")
	if err := os.WriteFile(huge, []byte(`{"pad":[`+strings.Repeat("0,", 3_000_000)+`0]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := map[string][2]string{
		"preToolUse":        {"permissionDecision", "permissionDecisionReason"},
		"permissionRequest": {"behavior", "message"},
	}
	failClosed := func(event string) map[string]any {
		k := keys[event]
		return map[string]any{k[0]: "deny", k[1]: "DefenseClaw hook failed closed"}
	}
	const failure = "failure"
	type adapterCase struct {
		name  string
		child string
		want  any // a decoded denial, or failure
	}
	casesFor := func(event string) []adapterCase {
		k, r := keys[event][0], keys[event][1]
		upper := strings.ToUpper(k[:1]) + k[1:]
		otherEvent := map[string]string{"preToolUse": "permissionRequest", "permissionRequest": "preToolUse"}[event]
		otherKey, otherReason := keys[otherEvent][0], keys[otherEvent][1]
		own := `{"` + k + `":"deny","` + r + `":"matched: test"}`
		return []adapterCase{
			{"own denial", own, map[string]any{k: "deny", r: "matched: test"}},
			{"own denial with CRLF and spaces", " \r\n" + own + "\r\n\t", map[string]any{k: "deny", r: "matched: test"}},
			{"case-colliding allow after the denial", `{"` + k + `":"deny","` + r + `":"policy","` + upper + `":"allow"}`, map[string]any{k: "deny", r: "policy"}},
			{"case-colliding allow before the denial", `{"` + upper + `":"allow","` + k + `":"deny","` + r + `":"policy"}`, map[string]any{k: "deny", r: "policy"}},
			{"case-colliding denial with the exact key allowing", `{"` + upper + `":"deny","` + k + `":"allow"}`, failure},
			{"denial under another case only", `{"` + upper + `":"deny"}`, failure},
			{"last duplicate denies", `{"` + k + `":"allow","` + k + `":"deny"}`, map[string]any{k: "deny"}},
			{"last duplicate allows", `{"` + k + `":"deny","` + k + `":"allow"}`, failure},
			{"escaped key and value", `{"` + k[:2] + `\u00` + strconv.FormatInt(int64(k[2]), 16) + k[3:] + `":"deny","` + r + `":"a \"q\" \\ \/ \n \u2028\u2029 café \ud83d\ude00 😀"}`, map[string]any{k: "deny", r: "a \"q\" \\ / \n \u2028\u2029 café \U0001F600 \U0001F600"}},
			{"non-string reason", `{"` + k + `":"deny","` + r + `":7}`, map[string]any{k: "deny"}},
			{"denial deeper than ConvertFrom-Json reads", `{"` + k + `":"deny","pad":` + strings.Repeat("[", 2000) + strings.Repeat("]", 2000) + `}`, map[string]any{k: "deny"}},
			{"array value", `{"` + k + `":["deny"]}`, failure},
			{"object value", `{"` + k + `":{"deny":"deny"}}`, failure},
			{"other case of the value", `{"` + k + `":"Deny"}`, failure},
			{"nested denial only", `{"hookSpecificOutput":{"` + k + `":"deny"}}`, failure},
			{"other event's denial", `{"` + otherKey + `":"deny","` + otherReason + `":"matched: test"}`, failure},
			{"two denials", own + "\n" + own, failure},
			{"allow", `{"permissionDecision":"allow","behavior":"allow"}`, failure},
			{"truncated denial", strings.TrimSuffix(own, "}"), failure},
			{"trailing text", own + "x", failure},
			{"trailing comma", `{"` + k + `":"deny",}`, failure},
			{"invalid number", `{"` + k + `":"deny","pad":01}`, failure},
			{"array of denials", "[" + own + "]", failure},
		}
	}
	type run struct {
		name, adapter, event, child, childFile string
		want                                   any
	}
	var runs []run
	for _, event := range []string{"preToolUse", "permissionRequest"} {
		cases := casesFor(event)
		for _, mode := range []string{"closed", "open", "refreshed release"} {
			for i, tc := range cases {
				if mode == "refreshed release" && i > 2 {
					break
				}
				want := tc.want
				if want == failure {
					want = nil
					if mode != "open" {
						want = failClosed(event)
					}
				}
				runs = append(runs, run{mode + "/" + event + "/" + tc.name, adapters[mode], event, tc.child, "", want})
			}
		}
		// A check that cannot finish inside the budget is doubt: it denies in
		// either fail mode.
		for _, mode := range []string{"closed", "open"} {
			runs = append(runs, run{mode + "/" + event + "/answer too large to check", adapters[mode+" budget"], event, "", huge, failClosed(event)})
		}
	}
	for _, r := range runs {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			env := []string{
				copilotAdapterHelperMode + "=crash-with-output",
				copilotAdapterChildStdoutEnv + "=" + r.child,
				copilotAdapterChildStdoutFileEnv + "=" + r.childFile,
			}
			stdout, stderr, code := runCopilotAdapterEventEnvTest(t, r.adapter, `{"source":"copilot-adapter-probe"}`, r.event, env)
			if code != 0 {
				t.Fatalf("exit %d stdout=%q stderr=%q", code, stdout, stderr)
			}
			got := decodeOneCopilotAnswer(t, stdout)
			if !reflect.DeepEqual(got, r.want) {
				t.Fatalf("answer = %#v, want %#v; stdout=%q stderr=%q", got, r.want, stdout, stderr)
			}
			if wantMap, _ := r.want.(map[string]any); wantMap == nil || wantMap[keys[r.event][1]] == "DefenseClaw hook failed closed" {
				if !strings.Contains(stderr, "exited with status 7") {
					t.Fatalf("stderr = %q, want the launcher status", stderr)
				}
			}
		})
	}
}

// decodeOneCopilotAnswer returns the one JSON object stdout holds, or nil
// for empty stdout. It fails on a duplicate key, a second document or
// trailing text, since Copilot would read those differently.
func decodeOneCopilotAnswer(t *testing.T, stdout string) any {
	t.Helper()
	if strings.TrimSpace(stdout) == "" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(stdout))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("answer %q is not one JSON object: %v %v", stdout, tok, err)
	}
	answer := map[string]any{}
	for dec.More() {
		tok, err := dec.Token()
		key, isKey := tok.(string)
		if err != nil || !isKey {
			t.Fatalf("answer %q: bad key %v %v", stdout, tok, err)
		}
		if _, dup := answer[key]; dup {
			t.Fatalf("answer %q repeats key %q", stdout, key)
		}
		var value any
		if err := dec.Decode(&value); err != nil {
			t.Fatalf("answer %q: %v", stdout, err)
		}
		answer[key] = value
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		t.Fatalf("answer %q is not one JSON object: %v %v", stdout, tok, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("answer %q has text after the object: %v", stdout, err)
	}
	return answer
}

func TestCopilotAdapterProductionDeadlineKillsChildAndFailsClosed(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv(copilotAdapterHelperMode, "timeout")
	t.Setenv(copilotAdapterPIDFileEnv, pidFile)
	adapter := renderCopilotAdapterForTest(t, executable, copilotWindowsHookAdapterTimeoutMS)
	startedAt := time.Now()
	stdout, stderr, code := runCopilotAdapterTest(
		t, adapter, `{"source":"copilot-adapter-probe"}`,
	)
	finishedAt := time.Now()
	pid, launchedAt := readAdapterLauncherRecord(t, pidFile, stderr)
	// PowerShell 5.1 startup is host-dependent and deliberately outside the
	// adapter's budget (it restarts the deadline once the launcher exists), so
	// the timeout plus the kill/drain reserve must fit the contract from there.
	elapsed := finishedAt.Sub(launchedAt)
	// Hosted Windows runners can pause this test process after the adapter
	// has already exited. The timeout diagnostic and child liveness below
	// check the adapter behavior; this wall-clock guard allows that pause.
	if elapsed > time.Duration(copilotWindowsHookContractTimeoutMS+5_000)*time.Millisecond {
		t.Fatalf("adapter exceeded the Copilot command-hook deadline: %s after the launcher started (%s including PowerShell startup)", elapsed, finishedAt.Sub(startedAt))
	}
	t.Logf("adapter finished %s after the launcher started (%s including PowerShell startup)", elapsed, finishedAt.Sub(startedAt))
	if code != 0 {
		t.Fatalf("exit code = %d, want native denial exit 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %q, want a native denial", stdout)
	}
	if !strings.Contains(stderr, fmt.Sprintf("timed out after %dms", copilotWindowsHookAdapterTimeoutMS)) {
		t.Fatalf("stderr = %q, want production timeout diagnostic", stderr)
	}
	if windowsProcessRunning(pid) {
		t.Fatalf("timed-out Copilot launcher process %d is still running", pid)
	}
}

func renderCursorAdapterForTest(t *testing.T, hookPath, failMode string, managed bool, timeoutMS int) string {
	t.Helper()
	rendered, err := renderWindowsCursorAdapter(hookPath, failMode, managed, timeoutMS)
	if err != nil {
		t.Fatalf("render Cursor adapter: %v", err)
	}
	path := filepath.Join(t.TempDir(), "cursor-hook.ps1")
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		t.Fatalf("write Cursor adapter: %v", err)
	}
	return path
}

func runCursorAdapterTest(
	t *testing.T,
	adapterPath string,
	payload string,
) (stdout, stderr string, exitCode int) {
	t.Helper()
	quoted := strings.ReplaceAll(adapterPath, "'", "''")
	cmd := exec.Command(
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$input | & '"+quoted+"'",
	)
	cmd.Stdin = strings.NewReader(payload)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err == nil {
		return out.String(), errOut.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run Cursor adapter: %v", err)
	}
	return out.String(), errOut.String(), exitErr.ExitCode()
}

func assertCursorAllowJSON(t *testing.T, stdout string) {
	t.Helper()
	if strings.TrimSpace(stdout) == "" {
		t.Fatal("Cursor adapter stdout is empty")
	}
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("Cursor adapter stdout is not valid JSON: %v", err)
	}
	if response["continue"] != true {
		t.Fatalf("Cursor adapter response = %#v, want continue=true", response)
	}
}

// windowsProcessRunning reports whether pid is still running after a short
// grace period. Kill only starts termination and the adapter waits for it
// with a bound, so the grace absorbs kernel teardown. Liveness comes from the
// process handle's signalled state, not GetExitCodeProcess, because a process
// may exit with STILL_ACTIVE (259). A PID that no longer exists counts as
// exited; any other open or wait failure counts as running so the caller's
// assertion fails safe.
func windowsProcessRunning(pid uint32) bool {
	const grace = 5 * time.Second
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return !errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer windows.CloseHandle(handle)
	result, err := windows.WaitForSingleObject(handle, uint32(grace.Milliseconds()))
	return err != nil || result != windows.WAIT_OBJECT_0
}

func TestCursorAdapterPreservesSuccessfulLauncherResponse(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cursorAdapterHelperMode, "success")
	// A cold Go test helper may take over a second to start on a loaded
	// Windows runner. This checks the successful response, not a 1 s budget.
	adapter := renderCursorAdapterForTest(t, executable, "closed", true, 5_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	assertCursorAllowJSON(t, stdout)
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestCursorAdapterTimeoutKillsChildThatDoesNotReadStdinAndFailsClosed(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv(cursorAdapterHelperMode, "timeout")
	t.Setenv(cursorAdapterPIDFileEnv, pidFile)
	// Use the production deadline. A shorter one can expire before a starved
	// helper has recorded its PID, which leaves nothing to check.
	adapter := renderCursorAdapterForTest(t, executable, "closed", true, cursorWindowsHookAdapterTimeoutMS)
	// Exceed the typical anonymous-pipe buffer so a synchronous stdin write
	// would remain stuck until the helper's sleep completed.
	payload := `{"source":"cursor-adapter-probe","padding":"` + strings.Repeat("x", 2<<20) + `"}`
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, payload,
	)
	finishedAt := time.Now()
	pid, launchedAt := readAdapterLauncherRecord(t, pidFile, stderr)
	// As for Copilot, the timeout plus the cleanup reserve must fit Cursor's
	// contract from the moment the launcher exists; PowerShell startup is
	// host-dependent and outside the adapter's budget.
	elapsed := finishedAt.Sub(launchedAt)
	if elapsed > time.Duration(cursorWindowsHookContractTimeoutMS)*time.Millisecond {
		t.Fatalf("adapter exceeded the Cursor command-hook deadline: %s after the launcher started", elapsed)
	}
	t.Logf("adapter finished %s after the launcher started", elapsed)
	if code != 2 {
		t.Fatalf("exit code = %d, want fail-closed 2; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"permission":"deny"`) {
		t.Fatalf("stdout = %q, want explicit deny", stdout)
	}
	if !strings.Contains(stderr, fmt.Sprintf("timed out after %dms", cursorWindowsHookAdapterTimeoutMS)) {
		t.Fatalf("stderr = %q, want timeout diagnostic", stderr)
	}
	if windowsProcessRunning(pid) {
		t.Fatalf("timed-out Cursor launcher process %d is still running", pid)
	}
}

func TestCursorAdapterExceptionEmitsFailClosedJSON(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCursorAdapterForTest(t, missingHook, "closed", true, 1_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`,
	)
	if code != 2 {
		t.Fatalf("exit code = %d, want fail-closed 2; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, `"permission":"deny"`) {
		t.Fatalf("stdout = %q, want explicit deny", stdout)
	}
	if !strings.Contains(stderr, "Cursor hook adapter failed") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
}

func TestCursorAdapterExceptionFailsOpenOnlyWhenConfigured(t *testing.T) {
	missingHook := filepath.Join(t.TempDir(), "missing-hook.exe")
	adapter := renderCursorAdapterForTest(t, missingHook, "open", false, 1_000)
	stdout, stderr, code := runCursorAdapterTest(
		t, adapter, `{"source":"cursor-adapter-probe"}`,
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want fail-open 0; stderr=%q", code, stderr)
	}
	assertCursorAllowJSON(t, stdout)
	if !strings.Contains(stderr, "Cursor hook adapter failed") {
		t.Fatalf("stderr = %q, want adapter failure diagnostic", stderr)
	}
}

func TestCursorAdapterPreservesLauncherBlockResponse(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(cursorAdapterHelperMode, "block")
	adapter := renderCursorAdapterForTest(t, executable, "closed", true, 1_000)
	stdout, stderr, code := runCursorAdapterTest(t, adapter, `{"source":"cursor-adapter-probe"}`)
	if code != 2 || !strings.Contains(stdout, `"permission":"deny"`) {
		t.Fatalf("block response=(code=%d stdout=%q stderr=%q), want exit 2 with deny", code, stdout, stderr)
	}
}

func TestCursorMappedAdapterUsesCurrentSIDNotPeerPolicy(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	peer := "S-1-5-21-9999-9999-9999-9999"
	if peer == sid {
		t.Fatal("test peer is current SID")
	}
	for _, failure := range []string{"missing", "timeout", "block"} {
		for _, mode := range []string{"open", "closed", "unenrolled"} {
			t.Run(failure+"/"+mode, func(t *testing.T) {
				modes := map[string]string{peer: "open"}
				if mode != "unenrolled" {
					modes[sid] = mode
				}
				if mode == "open" {
					modes[peer] = "closed"
				}
				hook := filepath.Join(t.TempDir(), "missing-hook.exe")
				if failure != "missing" {
					hook, err = os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					t.Setenv(cursorAdapterHelperMode, failure)
				}
				body, err := RenderWindowsCursorEnterpriseAdapterForTargets(hook, modes)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.ReplaceAll(body, []byte("$timeoutMs = 10000"), []byte("$timeoutMs = 1000"))
				adapter := filepath.Join(t.TempDir(), "cursor-hook.ps1")
				if err := os.WriteFile(adapter, body, 0o600); err != nil {
					t.Fatal(err)
				}
				stdout, stderr, code := runCursorAdapterTest(t, adapter, `{"source":"cursor-adapter-probe"}`)
				if mode == "open" && failure != "block" {
					if code != 0 {
						t.Fatalf("open user blocked: code=%d stderr=%q", code, stderr)
					}
					assertCursorAllowJSON(t, stdout)
					if !strings.Contains(stderr, "WARNING hook fail-open; inspection bypassed connector=cursor") {
						t.Fatal("missing fail-open diagnostic")
					}
				} else if code != 2 || !strings.Contains(stdout, `"permission":"deny"`) {
					t.Fatalf("closed/unenrolled user or valid denial allowed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
			})
		}
	}
}
