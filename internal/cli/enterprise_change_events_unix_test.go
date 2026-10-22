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

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubSecretChangeEnv(t *testing.T) (root string, layout managed.StandaloneLayout) {
	t.Helper()
	goos := enterpriseunix.CurrentGOOS()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Skip(err)
	}
	root = t.TempDir()
	previous := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 0 },
			Lchown: func(string, int, int) error { return nil }}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })
	return root, layout
}

func spoolEvents(t *testing.T, root string, layout managed.StandaloneLayout) ([]enterprisestatus.ChangeEvent, string) {
	t.Helper()
	dir := filepath.Join(root, enterprisestatus.ChangeEventsDir(layout.ConfigDir))
	var out []enterprisestatus.ChangeEvent
	var raw strings.Builder
	for _, id := range enterprisestatus.ListChangeEventIDs(dir) {
		path := filepath.Join(dir, id+".json")
		ev, err := enterprisestatus.ReadChangeEvent(path)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(path)
		raw.Write(data)
		out = append(out, ev)
	}
	return out, raw.String()
}

// Every Linux and macOS secret set or remove that changed a credential,
// failed or was refused leaves one change event; a run that changed
// nothing leaves none, and no event carries the value.
func TestUnixSecretChangesLeaveOneChangeEventEach(t *testing.T) {
	root, layout := stubSecretChangeEnv(t)

	// A bad --name is refused before the value is read: the name is left out.
	cmd := newEnterpriseSecretCommand("set", "")
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader("known-credential-value-7731\n"))
	opts := enterpriseSecretOptions{name: "BAD_NAME", fromStdin: true}
	if err := runEnterpriseSecret(cmd, "set", &opts); err == nil {
		t.Fatal("a bad name was accepted")
	}
	ok := enterprisestatus.New(enterpriseunix.ActionEnsure, "standalone", "linux", "1.0.4")
	ok.OK = true
	stored := unixSecretChange{ran: true, changed: true}
	recordUnixSecretChange(nil, "set", "splunk-hec-token", stored, ok, nil)
	recordUnixSecretChange(nil, "set", "splunk-hec-token", unixSecretChange{ran: true, existed: true}, ok, nil) // the stored value: nothing
	recordUnixSecretChange(nil, "remove", "absent-token", unixSecretChange{ran: true}, ok, nil)                 // nothing to remove
	recordUnixSecretChange(nil, "remove", "splunk-hec-token", unixSecretChange{ran: true, existed: true, changed: true}, ok, nil)
	failed := enterprisestatus.New(enterpriseunix.ActionEnsure, "standalone", "linux", "1.0.4")
	failed.AddError("apply_failed", "the ensure failed")
	recordUnixSecretChange(nil, "set", "otlp-token", unixSecretChange{ran: true}, failed, nil)
	// Written, then the ensure that applies it failed: the credential changed.
	recordUnixSecretChange(nil, "set", "judge-key", stored, failed, nil)
	recordUnixSecretChange(nil, "set", "judge-key", stored, nil, secretFailed("restart_failed", 1, errors.New("restart")))
	// The run ended before the change (a superseded apply): nothing written.
	superseded := enterprisestatus.New(enterpriseunix.ActionEnsure, "standalone", "linux", "1.0.4")
	superseded.OK, superseded.Noop, superseded.NoopReason = true, true, "superseded"
	recordUnixSecretChange(nil, "set", "late-token", unixSecretChange{}, superseded, nil)

	events, raw := spoolEvents(t, root, layout)
	want := []string{
		"set refused invalid_arguments ",
		"set applied  splunk-hec-token",
		"remove applied  splunk-hec-token",
		"set failed apply_failed otlp-token",
		"set applied  judge-key",
		"set applied  judge-key",
		"set refused superseded late-token",
	}
	var got []string
	for _, ev := range events {
		if ev.Kind != enterprisestatus.ChangeKindSecret || ev.Actor == "" {
			t.Fatalf("event = %+v", ev)
		}
		got = append(got, ev.Action+" "+ev.Outcome+" "+ev.ReasonCode+" "+ev.SecretName)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("events\n%q\nwant\n%q", got, want)
	}
	if strings.Contains(raw, "known-credential-value-7731") || strings.Contains(raw, "BAD_NAME") {
		t.Fatalf("the spool carries the value or the refused name:\n%s", raw)
	}
}

// A caller that is not root records nothing.
func TestUnixSecretChangeNeedsRoot(t *testing.T) {
	root, layout := stubSecretChangeEnv(t)
	previous := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		env, err := previous(goos)
		if env != nil {
			env.Geteuid = func() int { return 1000 }
		}
		return env, err
	}
	ok := enterprisestatus.New(enterpriseunix.ActionEnsure, "standalone", "linux", "1.0.4")
	ok.OK = true
	recordUnixSecretChange(nil, "set", "splunk-hec-token", unixSecretChange{ran: true, changed: true}, ok, nil)
	if events, _ := spoolEvents(t, root, layout); len(events) != 0 {
		t.Fatalf("a standard account recorded %+v", events)
	}
}

// A set that read its value records the change without the value, whatever
// the lifecycle run then did.
func TestUnixSecretSetChangeEventCarriesNoValue(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the lifecycle run after the read is exercised on Linux only")
	}
	root, layout := stubSecretChangeEnv(t)
	previousCaller := secretCallerPID
	secretCallerPID = func() int { return 4242 }
	t.Cleanup(func() { secretCallerPID = previousCaller })
	const value = "known-credential-value-9157"
	cmd := newEnterpriseSecretCommand("set", "")
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader(value + "\n"))
	opts := enterpriseSecretOptions{name: "splunk-hec-token", fromStdin: true}
	_ = runEnterpriseSecret(cmd, "set", &opts)
	events, raw := spoolEvents(t, root, layout)
	if len(events) != 1 || events[0].SecretName != "splunk-hec-token" || events[0].Action != "set" {
		t.Fatalf("events = %+v", events)
	}
	if strings.Contains(raw, value) {
		t.Fatalf("the change event carries the value:\n%s", raw)
	}
}

// blockChangeSpool puts a file where the change spool belongs, so no change
// event can be written.
func blockChangeSpool(t *testing.T, root string, layout managed.StandaloneLayout) {
	t.Helper()
	dir := filepath.Join(root, enterprisestatus.ChangeEventsDir(layout.ConfigDir))
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A secret set the device could not record is refused before anything is
// written, and a refusal that cannot be recorded says so on stderr
// (change_unrecorded) instead of passing silently.
func TestUnixSecretChangeThatCannotBeRecordedIsRefused(t *testing.T) {
	root, layout := stubSecretChangeEnv(t)
	blockChangeSpool(t, root, layout)
	cmd := newEnterpriseSecretCommand("set", "")
	stderr := &bytes.Buffer{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(stderr)
	cmd.SetIn(strings.NewReader("known-credential-value-4410\n"))
	opts := enterpriseSecretOptions{name: "splunk-hec-token", fromStdin: true}
	err := runEnterpriseSecret(cmd, "set", &opts)
	if err == nil || !strings.Contains(err.Error(), "cannot record the credential change") {
		t.Fatalf("set with no change spool: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, layout.SecretsDir, "splunk-hec-token")); statErr == nil {
		t.Fatal("the credential was written though its change could not be recorded")
	}
	if !strings.Contains(stderr.String(), "change_unrecorded") {
		t.Fatalf("stderr does not report the unrecorded refusal: %q", stderr.String())
	}
	ok := enterprisestatus.New(enterpriseunix.ActionEnsure, "standalone", "linux", "1.0.4")
	ok.OK = true
	if err := recordUnixSecretChange(nil, "remove", "splunk-hec-token", unixSecretChange{ran: true, existed: true, changed: true}, ok, nil); err == nil {
		t.Fatal("a change event that could not be written was not reported")
	}
}

// While another credential command holds the last place in the spool
// (between its check and its event), secret set is refused before the
// credential is written, and the other command still records its change.
// Before reservations both commands passed the check; the second changed
// the credential and could not record it.
func TestUnixSecretSetRefusedWhileAnotherChangeHoldsTheLastPlace(t *testing.T) {
	root, layout := stubSecretChangeEnv(t)
	env, err := newUnixLifecycleEnv(enterpriseunix.CurrentGOOS())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, enterprisestatus.ChangeEventsDir(layout.ConfigDir))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// enterprisestatus.maxPendingChangeEvents unreported events, less the
	// held place.
	for i := 0; i < 4096-1; i++ {
		ev, err := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionRemove,
			enterprisestatus.ChangeApplied, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ev.EventID+".json"), []byte("{}\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	held, err := env.ReserveChange(enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionRemove, "otlp-token")
	if err != nil {
		t.Fatalf("reserve the last place: %v", err)
	}
	defer held.Release()
	cmd := newEnterpriseSecretCommand("set", "")
	stderr := &bytes.Buffer{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(stderr)
	cmd.SetIn(strings.NewReader("known-credential-value-6620\n"))
	opts := enterpriseSecretOptions{name: "splunk-hec-token", fromStdin: true}
	if err := runEnterpriseSecret(cmd, "set", &opts); err == nil || !strings.Contains(err.Error(), "cannot record the credential change") {
		t.Fatalf("set with no room left: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, layout.SecretsDir, "splunk-hec-token")); statErr == nil {
		t.Fatal("the credential was written with no room left for its change event")
	}
	ok := enterprisestatus.New(enterpriseunix.ActionEnsure, "standalone", "linux", "1.0.4")
	ok.OK = true
	if err := recordUnixSecretChange(held, "remove", "otlp-token", unixSecretChange{ran: true, existed: true, changed: true}, ok, nil); err != nil {
		t.Fatalf("the command that held the place could not record its change: %v", err)
	}
	if got := len(enterprisestatus.ListChangeEventIDs(dir)); got != 4096 {
		t.Fatalf("spool holds %d events, want 4096", got)
	}
}

// fakeSecretAccounts finds no gateway service account, so a credential is
// staged root-only. pause, when set, runs first.
type fakeSecretAccounts struct {
	enterpriseunix.AccountManager
	pause func()
}

func (a fakeSecretAccounts) Lookup(context.Context, string) (enterpriseunix.Account, bool, error) {
	if a.pause != nil {
		a.pause()
	}
	return enterpriseunix.Account{}, false, nil
}

// ensureAfterChange is the lifecycle run of a secret command: it writes or
// removes the credential (opts.Mutate) as Run does, then, after after,
// fails the ensure that applies the change.
func ensureAfterChange(after func()) func(context.Context, *enterpriseunix.Env, enterpriseunix.Options) *enterprisestatus.Result {
	return func(ctx context.Context, _ *enterpriseunix.Env, opts enterpriseunix.Options) *enterprisestatus.Result {
		result := enterprisestatus.New(enterpriseunix.ActionEnsure, "standalone", "linux", "1.0.4")
		if err := opts.Mutate(ctx); err != nil {
			result.AddError("change_failed", err.Error())
			return result
		}
		if after != nil {
			after()
		}
		result.AddError("apply_failed", "the gateway did not start on the changed credential")
		return result
	}
}

// A set or remove that wrote or removed the credential is recorded applied
// when the ensure after it fails; the command still fails. A write that did
// not happen stays failed.
func TestUnixSecretChangeAppliedWhenTheEnsureAfterItFails(t *testing.T) {
	root, layout := stubSecretChangeEnv(t)
	stub := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		env, err := stub(goos)
		if env != nil {
			env.Accounts = fakeSecretAccounts{}
		}
		return env, err
	}
	previousRun, previousCaller := unixSecretLifecycle, secretCallerPID
	unixSecretLifecycle, secretCallerPID = ensureAfterChange(nil), func() int { return 4242 }
	t.Cleanup(func() { newUnixLifecycleEnv, unixSecretLifecycle, secretCallerPID = stub, previousRun, previousCaller })
	run := func(action string) error {
		cmd := newEnterpriseSecretCommand(action, "")
		cmd.SetContext(context.Background())
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetIn(strings.NewReader("provided by secret store\n"))
		opts := enterpriseSecretOptions{name: "judge-key", fromStdin: action == "set", json: true}
		return runEnterpriseSecret(cmd, action, &opts)
	}
	secrets := filepath.Join(root, layout.SecretsDir)
	if err := run("set"); err == nil {
		t.Fatal("secret set reported success though the ensure failed")
	}
	if _, err := os.Lstat(filepath.Join(secrets, "judge-key")); err != nil {
		t.Fatalf("the credential was not stored: %v", err)
	}
	if err := run("remove"); err == nil {
		t.Fatal("secret remove reported success though the ensure failed")
	}
	if _, err := os.Lstat(filepath.Join(secrets, "judge-key")); !os.IsNotExist(err) {
		t.Fatalf("the credential was not removed: %v", err)
	}
	// The credential store is unusable: nothing is written.
	if err := os.RemoveAll(secrets); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secrets, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("set"); err == nil {
		t.Fatal("secret set into an unusable store succeeded")
	}
	events, _ := spoolEvents(t, root, layout)
	var got []string
	for _, ev := range events {
		got = append(got, ev.Action+" "+ev.Outcome+" "+ev.ReasonCode+" "+ev.SecretName)
	}
	sort.Strings(got)
	want := []string{"remove applied  judge-key", "set applied  judge-key", "set failed change_failed judge-key"}
	if !slices.Equal(got, want) {
		t.Fatalf("events\n%q\nwant\n%q", got, want)
	}
	if entries, err := os.ReadDir(filepath.Join(root, layout.LifecycleDir, "change-reservations")); err != nil || len(entries) != 0 {
		t.Fatalf("reservations remain: %v (%v)", entries, err)
	}
}

// A secret set killed after it marked the credential file but before it
// wrote it is failed (interrupted), with nothing stored; one killed after it
// wrote the credential, while the ensure applies it, is applied. The next
// writer records each once.
func TestUnixSecretSetKilledAfterTheChangeIsRecordedApplied(t *testing.T) {
	const childRoot, childPoint = "DC_TEST_SECRET_KILL_ROOT", "DC_TEST_SECRET_KILL_POINT"
	if root := os.Getenv(childRoot); root != "" {
		layout, err := managed.StandaloneLayoutFor(enterpriseunix.CurrentGOOS())
		if err != nil {
			t.Fatal(err)
		}
		reached := func() {
			if err := os.WriteFile(filepath.Join(root, "kill-point-reached"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Hour)
		}
		accounts := fakeSecretAccounts{}
		if os.Getenv(childPoint) == "marked" {
			// The account lookup of the write, after the mark (the
			// reservation's own lookup comes before it).
			accounts.pause = func() {
				if marks, _ := filepath.Glob(filepath.Join(root, layout.LifecycleDir, "change-reservations", "*.target")); len(marks) == 1 {
					reached()
				}
			}
		}
		newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
			return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Accounts: accounts,
				Geteuid: func() int { return 0 }, Lchown: func(string, int, int) error { return nil }}, nil
		}
		unixSecretLifecycle, secretCallerPID = ensureAfterChange(reached), func() int { return 4242 }
		cmd := newEnterpriseSecretCommand("set", "")
		cmd.SetContext(context.Background())
		var diagnostics bytes.Buffer
		cmd.SetOut(&diagnostics)
		cmd.SetErr(&diagnostics)
		cmd.SetIn(strings.NewReader("provided by secret store\n"))
		opts := enterpriseSecretOptions{name: "killed-token", fromStdin: true}
		err = runEnterpriseSecret(cmd, "set", &opts)
		t.Fatalf("secret set finished before its kill point: %v: %s", err, &diagnostics)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		point, outcome, code string
		stored               bool
	}{
		{"marked", enterprisestatus.ChangeFailed, enterprisestatus.ChangeInterrupted, false},
		{"changed", enterprisestatus.ChangeApplied, "", true},
	} {
		t.Run(tc.point, func(t *testing.T) {
			root, layout := stubSecretChangeEnv(t)
			child := exec.Command(binary, "-test.run=^TestUnixSecretSetKilledAfterTheChangeIsRecordedApplied$")
			child.Env = append(os.Environ(), childRoot+"="+root, childPoint+"="+tc.point)
			var output bytes.Buffer
			child.Stdout, child.Stderr = &output, &output
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			t.Cleanup(func() { _ = child.Process.Kill() })
			deadline := time.NewTimer(20 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				if _, err := os.Stat(filepath.Join(root, "kill-point-reached")); err == nil {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("set ended before its kill point: %v: %s", err, &output)
				case <-deadline.C:
					t.Fatalf("set did not reach its kill point: %s", &output)
				case <-tick.C:
				}
			}
			if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			<-done
			env, err := newUnixLifecycleEnv(enterpriseunix.CurrentGOOS())
			if err != nil {
				t.Fatal(err)
			}
			env.Accounts = fakeSecretAccounts{}
			for i := 0; i < 2; i++ {
				held, err := env.ReserveChange(enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionSet, "later-token")
				if err != nil {
					t.Fatal(err)
				}
				held.Release()
			}
			events, _ := spoolEvents(t, root, layout)
			if len(events) != 1 || events[0].SecretName != "killed-token" || events[0].Outcome != tc.outcome ||
				events[0].ReasonCode != tc.code {
				t.Fatalf("killed set events = %+v", events)
			}
			if entries, err := os.ReadDir(filepath.Join(root, layout.LifecycleDir, "change-reservations")); err != nil || len(entries) != 0 {
				t.Fatalf("reservations or marks remain: %v (%v)", entries, err)
			}
			if _, err := os.Lstat(filepath.Join(root, layout.SecretsDir, "killed-token")); (err == nil) != tc.stored {
				t.Fatalf("credential stored = %v, want %v", err == nil, tc.stored)
			}
		})
	}
}

type secretLockWaitServices struct{ enterpriseunix.ServiceManager }

func (secretLockWaitServices) Check(context.Context) error { return nil }
func (secretLockWaitServices) Version(context.Context) int { return 0 }

// The reservation must already exist while set waits for the lifecycle
// lock. A killed writer is reported exactly once without storing a value.
func TestUnixSecretSetInterruptedDuringLockWait(t *testing.T) {
	const childRoot = "DC_TEST_SECRET_LOCK_ROOT"
	if root := os.Getenv(childRoot); root != "" {
		layout, err := managed.StandaloneLayoutFor(enterpriseunix.CurrentGOOS())
		if err != nil {
			t.Fatal(err)
		}
		nowCalls := 0
		newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
			return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout,
				Services: secretLockWaitServices{},
				Geteuid:  func() int { return 0 }, Lchown: func(string, int, int) error { return nil },
				Now: func() time.Time {
					nowCalls++
					// acquireLock reads its deadline first; flockUntil reads
					// the clock again only after flock reports the lock busy.
					if nowCalls == 2 {
						if err := os.WriteFile(filepath.Join(root, "lock-wait-entered"), nil, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					return time.Now()
				}}, nil
		}
		cmd := newEnterpriseSecretCommand("set", "")
		cmd.SetContext(context.Background())
		var diagnostics bytes.Buffer
		cmd.SetOut(&diagnostics)
		cmd.SetErr(&diagnostics)
		cmd.SetIn(strings.NewReader("provided by secret store\n"))
		opts := enterpriseSecretOptions{name: "interrupted-token", fromStdin: true, lockWait: time.Minute}
		if err := runEnterpriseSecret(cmd, "set", &opts); err != nil {
			t.Fatalf("%v: %s", err, &diagnostics)
		}
		t.Fatal("secret set finished while another process held the lifecycle lock")
	}
	root, layout := stubSecretChangeEnv(t)
	stateDir := filepath.Join(root, layout.LifecycleDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(stateDir, "lifecycle.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(binary, "-test.run=^TestUnixSecretSetInterruptedDuringLockWait$")
	child.Env = append(os.Environ(), childRoot+"="+root)
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	t.Cleanup(func() { _ = child.Process.Kill() })
	reservations := filepath.Join(stateDir, "change-reservations")
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		entries, _ := os.ReadDir(reservations)
		_, waiting := os.Stat(filepath.Join(root, "lock-wait-entered"))
		if len(entries) == 1 && waiting == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("set ended before its reservation: %v: %s", err, &output)
		case <-deadline.C:
			t.Fatal("set did not reserve its audit event before waiting on the lifecycle lock")
		case <-tick.C:
		}
	}
	secret := filepath.Join(root, layout.SecretsDir, "interrupted-token")
	if _, err := os.Lstat(secret); !os.IsNotExist(err) {
		t.Fatalf("waiting set stored a credential: %v", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("killed set succeeded")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	env, err := newUnixLifecycleEnv(enterpriseunix.CurrentGOOS())
	if err != nil {
		t.Fatal(err)
	}
	// Repeated later writers settle the killed command only once.
	for i := 0; i < 2; i++ {
		held, err := env.ReserveChange(enterprisestatus.ChangeKindSecret, enterprisestatus.ChangeActionSet, "later-token")
		if err != nil {
			t.Fatal(err)
		}
		held.Release()
	}
	events, _ := spoolEvents(t, root, layout)
	if len(events) != 1 || events[0].SecretName != "interrupted-token" ||
		events[0].Outcome != enterprisestatus.ChangeFailed || events[0].ReasonCode != enterprisestatus.ChangeInterrupted {
		t.Fatalf("interrupted set events = %+v", events)
	}
	if entries, err := os.ReadDir(reservations); err != nil || len(entries) != 0 {
		t.Fatalf("reservations remain: %v (%v)", entries, err)
	}
	if _, err := os.Lstat(secret); !os.IsNotExist(err) {
		t.Fatalf("killed set stored a credential: %v", err)
	}
}
