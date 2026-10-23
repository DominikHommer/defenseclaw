// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Shell fragments for the tests below. $1 is the pid file. The escaped
// child writes its own pid as this test sees it (/proc/self, not $$, which
// counts in the command's PID namespace), then runs as sleep with that pid.
const (
	containChild     = `sh -c 'read -r p _ < /proc/self/stat; echo $p > "$0"; exec sleep 60' "$1" </dev/null >/dev/null 2>&1`
	containClosedFDs = `sh -c 'read -r p _ < /proc/self/stat; echo $p > "$0"; exec sleep 60 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-' "$1" </dev/null >/dev/null 2>&1`
	containWaitPID   = `while [ ! -s "$1" ]; do sleep 0.01; done`
	containNewGroup  = `perl -e 'setpgrp(0, 0) or die; exec @ARGV or die' `
)

// containRunners are the two Linux supervisors: the PID namespace runner and
// the subreaper custodian scanners keep.
var containRunners = map[string]func(*exec.Cmd) error{"RunContained": RunContained, "RunTracked": RunTracked}

func requireContainTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"setsid", "perl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
}

// r104 W5b: RunTree kills the command's process group only. A descendant in
// a session or group of its own outlived it, and the Hermes probe passed.
func TestRunContainedEndsDescendantsThatLeaveTheGroup(t *testing.T) {
	requireContainTools(t)
	for _, tc := range []struct {
		name    string
		script  string
		timeout time.Duration
		wantErr bool
	}{
		{"new session", "setsid " + containChild + " &\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"double fork into a new session", "( setsid " + containChild + " & )\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"new session, inherited descriptors closed", "setsid " + containClosedFDs + " &\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"own process group", containNewGroup + containChild + " &\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"session leader that forks again", `setsid sh -c '( sh -c "read -r p _ < /proc/self/stat; echo \$p > \"\$0\"; exec sleep 60" "$0" & ) ; exit 0' "$1" </dev/null >/dev/null 2>&1 &` + "\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"canceled", "setsid " + containChild + " &\n" + containWaitPID + "\nsleep 60", 500 * time.Millisecond, true},
	} {
		for name, run := range containRunners {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				pidFile := filepath.Join(t.TempDir(), "escaped.pid")
				ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
				defer cancel()
				cmd := CommandContext(ctx, "/bin/sh", "-c", tc.script, "sh", pidFile)
				cmd.WaitDelay = time.Second
				err := run(cmd)
				pid := readContainPID(t, pidFile)
				if helperRunning(pid) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("%s returned (%v) while descendant %d still runs", name, err, pid)
				}
				if (err != nil) != tc.wantErr {
					t.Fatalf("%s = %v, want error %v", name, err, tc.wantErr)
				}
			})
		}
	}
}

// Where the runner's namespaces cannot be created, the command never runs.
func TestRunContainedFailsClosedWithoutANamespace(t *testing.T) {
	if effectiveCapabilities() != 0 {
		t.Skip("a privileged process maps no IDs of its own")
	}
	previous := containIDMap
	containIDMap = func(id int) []syscall.SysProcIDMap {
		return []syscall.SysProcIDMap{{ContainerID: id, HostID: id + 1, Size: 1}}
	}
	t.Cleanup(func() { containIDMap = previous })
	ran := filepath.Join(t.TempDir(), "ran")
	err := RunContained(CommandContext(context.Background(), "/bin/sh", "-c", `: > "$1"`, "sh", ran))
	if !errors.Is(err, ErrNotContained) {
		t.Fatalf("RunContained = %v, want ErrNotContained", err)
	}
	if _, statErr := os.Stat(ran); statErr == nil {
		t.Fatal("the command ran outside a namespace of its own")
	}
}

// A privileged caller (root without CAP_SYS_ADMIN, as in the hook guardian's
// unit) keeps every file's owner in the namespace.
func TestRunContainedKeepsFileOwnersWhenPrivileged(t *testing.T) {
	caps := effectiveCapabilities()
	if caps&(1<<unix.CAP_SYS_ADMIN) == 0 && (caps&(1<<unix.CAP_SETUID) == 0 || caps&(1<<unix.CAP_SETGID) == 0) {
		t.Skip("needs CAP_SYS_ADMIN or CAP_SETUID and CAP_SETGID")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "owned")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const uid, gid = 4242, 4343
	if err := os.Chown(file, uid, gid); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `stat -c %u:%g "$1"`, "sh", file)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunContained(cmd); err != nil {
		t.Fatalf("RunContained = %v: %s", err, out.String())
	}
	if got, want := strings.TrimSpace(out.String()), strconv.Itoa(uid)+":"+strconv.Itoa(gid); got != want {
		t.Fatalf("owner in the namespace = %q, want %q", got, want)
	}
}

const containGuardianHelperEnv = "DC_PROCESSUTIL_CONTAIN_GUARDIAN_HELPER"

// TestRunContainedGuardianHelper is the helper process of
// TestRunContainedAsTheGuardianActingAsAUser: as the root hook guardian does
// for a user's probe, it keeps its real root IDs and acts as nobody.
func TestRunContainedGuardianHelper(t *testing.T) {
	if os.Getenv(containGuardianHelperEnv) == "" {
		t.Skip("helper process of TestRunContainedAsTheGuardianActingAsAUser")
	}
	if syscall.Setegid(65534) != nil || syscall.Seteuid(65534) != nil {
		os.Exit(3)
	}
	cmd := exec.Command("/bin/sh", "-c", `echo "$(id -u) $(id -ru) $(id -g) $(id -rg)"`)
	cmd.Stdout = os.Stdout
	if err := RunContained(cmd); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

// The root hook guardian runs a user's probe with its real IDs still root.
// It could not write its child's ID maps (it is not dumpable then), and the
// probe ran the user's hook with the guardian's real root UID.
func TestRunContainedAsTheGuardianActingAsAUser(t *testing.T) {
	if os.Getenv(containGuardianHelperEnv) != "" {
		t.Skip("running as the helper")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(self, "-test.run=^TestRunContainedGuardianHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), containGuardianHelperEnv+"=1")
	helper.Dir = "/"
	out, err := helper.Output()
	if err != nil {
		t.Fatalf("helper = %v:\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "65534 65534 65534 65534" {
		t.Fatalf("probe ran as %q, want the user's IDs alone", out)
	}
}

// When the supervisor cannot sweep what is left, the run fails closed.
func TestRunTrackedFailsClosedWhenItCannotEndTheTree(t *testing.T) {
	requireContainTools(t)
	previous := containSweepBudget
	containSweepBudget = 0
	t.Cleanup(func() { containSweepBudget = previous })
	pidFile := filepath.Join(t.TempDir(), "escaped.pid")
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c",
		"setsid "+containChild+" &\n"+containWaitPID+"\nexit 0", "sh", pidFile))
	pid := readContainPID(t, pidFile)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	if !errors.Is(err, ErrNotContained) {
		t.Fatalf("RunTracked = %v, want ErrNotContained", err)
	}
}

// A command that kills its supervisor cannot pass.
func TestRunTrackedFailsWhenTheSupervisorIsKilled(t *testing.T) {
	requireContainTools(t)
	// RunContained is also called by the long-lived gateway. Its custodian
	// must never sweep another child of the gateway while ending this probe.
	unrelated := exec.Command("sleep", "60")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
	})
	pidFile := filepath.Join(t.TempDir(), "escaped.pid")
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c",
		"setsid "+containChild+" &\n"+containWaitPID+"\n"+
			// Only ever the supervisor: never the test binary.
			`case "$(tr '\0' ' ' < /proc/$PPID/cmdline)" in `+containSupervisorArg0+`*) kill -9 $PPID ;; esac`+
			"\nexit 0", "sh", pidFile))
	pid := readContainPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if err == nil {
		t.Fatal("RunTracked passed after the command killed its supervisor")
	}
	if helperRunning(pid) {
		t.Fatalf("RunTracked returned after its supervisor died while descendant %d still runs", pid)
	}
	if !helperRunning(unrelated.Process.Pid) {
		t.Fatalf("RunContained killed unrelated gateway child %d", unrelated.Process.Pid)
	}
}

// Scanner runtimes use positive PIDs to stop their own helpers. In particular,
// Python's subprocess timeout kills by PID before it can return to the caller.
func TestRunTrackedCanStopItsOwnChildByPID(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := CommandContext(context.Background(), "/bin/sh", "-c",
		`sleep 60 & child=$!; echo "$child" > "$1"; kill -TERM "$child" || exit 11; wait "$child"; [ "$?" -eq 143 ]`,
		"sh", pidFile)
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("RunTracked could not stop its child by PID: %v", err)
	}
	pid := readContainPID(t, pidFile)
	if helperRunning(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("child %d still runs after a successful wait", pid)
	}
}

func TestRunTrackedPythonSubprocessTimeout(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := CommandContext(ctx, python, "-c", `import subprocess
try:
    subprocess.run(["sleep", "60"], timeout=0.1, check=True)
except subprocess.TimeoutExpired:
    print("timeout handled")
else:
    raise AssertionError("sleep did not time out")`)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("Python could not handle the subprocess timeout: %v: %s", err, out.String())
	}
	if strings.TrimSpace(out.String()) != "timeout handled" {
		t.Fatalf("Python timeout result = %q", out.String())
	}
}

// If the custodian is unexpectedly killed, the gateway adopts the scanner's
// orphan. An unrelated gateway child started during the scan must survive the
// emergency sweep.
func TestRunTrackedAdoptsOnlyTheDeadCustodiansChildren(t *testing.T) {
	requireContainTools(t)
	dir := t.TempDir()
	childFile, custodianFile := filepath.Join(dir, "child.pid"), filepath.Join(dir, "custodian.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := CommandContext(ctx, "/bin/sh", "-c",
		// Keep stdout open in the detached child. Cmd.Wait must not wait for
		// that pipe before the gateway can end the adopted child.
		`setsid sh -c 'read -r p _ < /proc/self/stat; echo "$p" > "$0"; exec sleep 60' "$1" &`+
			"\n"+containWaitPID+"\n"+
			`read -r _ _ _ custodian _ < /proc/$PPID/stat; echo "$custodian" > "$2"; sleep 60`,
		"sh", childFile, custodianFile)
	cmd.Stdout = io.Discard
	done := make(chan error, 1)
	go func() { done <- RunTracked(cmd) }()
	child := readContainPID(t, childFile)
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })
	custodian := readContainPID(t, custodianFile)
	unrelated := exec.Command("sleep", "60")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
	})
	if err := syscall.Kill(custodian, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunTracked passed after its custodian was killed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunTracked did not return after the custodian was killed")
	}
	if helperRunning(child) {
		t.Fatalf("scanner child %d survived the custodian", child)
	}
	if !helperRunning(unrelated.Process.Pid) {
		t.Fatalf("unrelated gateway child %d was killed", unrelated.Process.Pid)
	}
}

// When the runner dies, however it dies, nothing the command started is left:
// the kernel ends the runner's namespace with it. RunContained is also called
// by the long-lived gateway, so an unrelated gateway child must survive.
func TestRunContainedEndsTheTreeWhenTheRunnerIsKilled(t *testing.T) {
	requireContainTools(t)
	unrelated := exec.Command("sleep", "60")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
	})
	dir := t.TempDir()
	pidFile, runnerFile := filepath.Join(dir, "escaped.pid"), filepath.Join(dir, "runner.pid")
	done := make(chan error, 1)
	go func() {
		done <- RunContained(CommandContext(context.Background(), "/bin/sh", "-c",
			"setsid "+containChild+" &\n"+containWaitPID+"\n"+
				`read -r _ _ _ a _ < /proc/self/stat; echo $a > "$2"; sleep 60`, "sh", pidFile, runnerFile))
	}()
	pid := readContainPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	runner := readContainPID(t, runnerFile)
	if err := syscall.Kill(runner, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunContained passed after its runner was killed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunContained did not return after its runner was killed")
	}
	if helperRunning(pid) {
		t.Fatalf("RunContained returned after its runner died while descendant %d still runs", pid)
	}
	if !helperRunning(unrelated.Process.Pid) {
		t.Fatalf("RunContained killed unrelated gateway child %d", unrelated.Process.Pid)
	}
}

// r104 W5b review: a hook that SIGKILLed the subreaper custodian, its
// grandparent, took the runner and itself down with it, and the kernel handed
// its setsid child to init, which kept running; the same held for a scanner
// below RunTracked (GAP-0631). The command must not be able to end anything
// that contains it, whichever ancestor it targets and however it signals,
// and nothing it started may outlive the run.
func TestRunContainedSurvivesTheCommandKillingEverySupervisor(t *testing.T) {
	requireContainTools(t)
	// Collect every supervisor ancestor by the pids this test sees, outermost
	// first, and SIGKILL them together, one by one and by process group.
	ancestors := `read -r _ _ _ a _ < /proc/self/stat; list=""
while [ "${a:-0}" -gt 1 ]; do
  case "$(tr '\0' ' ' < /proc/$a/cmdline)" in ` + containSupervisorArg0 + `*) list="$a $list" ;; esac
  read -r _ _ _ a _ < /proc/$a/stat || break
done
[ -n "$list" ] || exit 7
`
	for _, kill := range []struct {
		name, script string
		amd64        bool // raw amd64 system call numbers
		trackedOnly  bool
	}{
		{"kill", `kill -9 $list`, false, false},
		{"process groups", `for p in $list; do kill -9 -$p; done`, false, false},
		{"perl", `perl -e 'kill 9, @ARGV' $list`, false, false},
		{"tgkill", `perl -e 'syscall(234, $_+0, $_+0, 9) for @ARGV' $list`, true, false},
		{"tkill", `for p in $list; do for t in /proc/$p/task/*; do perl -e 'syscall(200, $ARGV[0]+0, 9)' "${t##*/}"; done; done`, true, false},
		{"pidfd", `perl -e 'for (@ARGV) { my $fd = syscall(434, $_+0, 0); syscall(424, $fd, 9, 0, 0) if $fd >= 0 }' $list`, false, false},
		{"I/O owner", `perl -e 'for (@ARGV) { pipe(my $r, my $w) or die; fcntl($r, 8, $_+0); fcntl($r, 10, 9); fcntl($r, 4, 020000); syswrite($w, "x") }' $list`, false, false},
		{"socket owner", `perl -MSocket -e 'for (@ARGV) { socketpair(my $r, my $w, AF_UNIX, SOCK_STREAM, 0) or die; ioctl($r, 0x8901, pack("i", $_)); fcntl($r, 10, 9); fcntl($r, 4, 020000); syswrite($w, "x") }' $list`, false, false},
		{"sigqueue", `perl -e 'for (@ARGV) { my $i = pack("iii", 9, 0, -1) . "\0" x 116; syscall(129, $_+0, 9, $i) }' $list`, true, false},
		{"kill by thread ID", `set -- $list; p=$1; t=$p; for path in /proc/$p/task/*; do [ "${path##*/}" != "$p" ] && { t=${path##*/}; break; }; done; [ "$t" != "$p" ] || exit 7; kill -9 "$t"`, false, true},
		{"sigqueue by thread ID", `set -- $list; p=$1; t=$p; for path in /proc/$p/task/*; do [ "${path##*/}" != "$p" ] && { t=${path##*/}; break; }; done; [ "$t" != "$p" ] || exit 7; perl -e 'my $i = pack("iii", 9, 0, -1) . "\0" x 116; syscall(129, $ARGV[0]+0, 9, $i)' "$t"`, true, true},
		{"I/O owner by thread ID", `set -- $list; p=$1; t=$p; for path in /proc/$p/task/*; do [ "${path##*/}" != "$p" ] && { t=${path##*/}; break; }; done; [ "$t" != "$p" ] || exit 7; perl -e 'pipe(my $r, my $w) or die; fcntl($r, 8, $ARGV[0]+0); fcntl($r, 10, 9); fcntl($r, 4, 020000); syswrite($w, "x")' "$t"`, false, true},
		{"prlimit custodian", `set -- $list; perl -e 'my $limit = pack("QQ", 0, 0); syscall(302, $ARGV[0]+0, 7, $limit, 0)' "$1"`, true, true},
		{"join custodian group then kill zero", `set -- $list; perl -e 'syscall(109, 0, $ARGV[0]+0) == 0 or die "setpgid: $!"; kill 9, 0' "$1"`, true, true},
	} {
		for name, run := range containRunners {
			t.Run(name+"/"+kill.name, func(t *testing.T) {
				if kill.trackedOnly && name != "RunTracked" {
					t.Skip("the PID-namespace runner has no subreaper custodian")
				}
				if kill.amd64 && runtime.GOARCH != "amd64" {
					t.Skip("raw syscall numbers are amd64's")
				}
				pidFile := filepath.Join(t.TempDir(), "escaped.pid")
				err := run(CommandContext(context.Background(), "/bin/sh", "-c",
					"setsid "+containChild+" &\n"+containWaitPID+"\n"+ancestors+kill.script+"\nsleep 1\nexit 0", "sh", pidFile))
				pid := readContainPID(t, pidFile)
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) && exitErr.ExitCode() == 7 {
					t.Fatal("the command found no supervisor ancestor")
				}
				if helperRunning(pid) {
					t.Fatalf("%s returned (%v) while descendant %d still runs", name, err, pid)
				}
			})
		}
	}
}

// The custodian is not dumpable, so the command cannot trace it and make it
// exit (GAP-0631): its /proc entries belong to root.
func TestRunTrackedCustodianIsNotDumpable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every /proc entry it has")
	}
	var out strings.Builder
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `read -r _ _ _ a _ < /proc/self/stat
while [ "${a:-0}" -gt 1 ]; do
  case "$(tr '\0' ' ' < /proc/$a/cmdline)" in "`+containSupervisorArg0+` `+containCustodianMode+` "*) stat -c %u /proc/$a/status; exit 0 ;; esac
  read -r _ _ _ a _ < /proc/$a/stat || break
done
exit 7`)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("RunTracked = %v: %s", err, out.String())
	}
	if got := strings.TrimSpace(out.String()); got != "0" {
		t.Fatalf("the custodian's /proc status belongs to %q, want root (not dumpable)", got)
	}
}

func TestRunTrackedRunnerIsNotDumpable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every /proc entry it has")
	}
	var out strings.Builder
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `stat -c %u /proc/$PPID/status`)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("RunTracked = %v: %s", err, out.String())
	}
	if got := strings.TrimSpace(out.String()); got != "0" {
		t.Fatalf("the runner's /proc status belongs to %q, want root (not dumpable)", got)
	}
}

const containInjectionHelperEnv = "DC_PROCESSUTIL_INJECTION_HELPER"

func TestRunTrackedCannotInjectIntoRunnerHelper(t *testing.T) {
	if os.Getenv(containInjectionHelperEnv) == "" {
		t.Skip("helper process of TestRunTrackedCannotInjectIntoRunner")
	}
	parent := uintptr(os.Getppid())
	// PTRACE_SEIZE does not stop the runner. If it succeeds, detach before
	// reporting the failure so the test cannot strand its supervisor.
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, 0x4206, parent, 0, 0, 0, 0)
	if errno == 0 {
		_, _, _ = unix.Syscall6(unix.SYS_PTRACE, 17, parent, 0, 0, 0, 0)
		t.Fatal("scanner attached to its runner")
	}
	if errno != unix.EPERM {
		t.Fatalf("ptrace runner = %v, want EPERM", errno)
	}
	for _, call := range []struct {
		name string
		nr   uintptr
	}{
		{"process_vm_readv", unix.SYS_PROCESS_VM_READV},
		{"process_vm_writev", unix.SYS_PROCESS_VM_WRITEV},
	} {
		_, _, errno := unix.Syscall6(call.nr, parent, 0, 0, 0, 0, 0)
		if errno != unix.EPERM {
			t.Errorf("%s runner = %v, want EPERM", call.name, errno)
		}
	}
	fd, err := unix.PidfdOpen(int(parent), 0)
	if err != nil {
		t.Fatalf("pidfd_open runner: %v", err)
	}
	defer unix.Close(fd)
	if _, err := unix.PidfdGetfd(fd, 0, 0); err != unix.EPERM {
		t.Errorf("pidfd_getfd runner = %v, want EPERM", err)
	}
}

func TestRunTrackedCannotInjectIntoRunner(t *testing.T) {
	raw, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil || strings.TrimSpace(string(raw)) != "0" {
		t.Skip("requires Yama ptrace_scope=0")
	}
	cmd := CommandContext(context.Background(), os.Args[0], "-test.run=^TestRunTrackedCannotInjectIntoRunnerHelper$")
	cmd.Env = append(os.Environ(), containInjectionHelperEnv+"=1")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("injection probe = %v: %s", err, out.String())
	}
}

func TestCustodianGuardFilterHandlesManyProtectedThreads(t *testing.T) {
	protected := make([]uint32, 128)
	for i := range protected {
		protected[i] = uint32(1000 + i)
	}
	group := int32(2000)
	filter, err := custodianGuardFilter(1000, 2000, uint32(-group), protected)
	if err != nil {
		t.Fatal(err)
	}
	if len(filter) > 4096 {
		t.Fatalf("seccomp filter has %d instructions, kernel limit is 4096", len(filter))
	}
}

const containDeathHelperEnv = "DC_PROCESSUTIL_CONTAIN_DEATH_HELPER"

// TestRunContainedDeathHelper is the helper process of
// TestRunContainedEndsTheTreeWhenTheGatewayDies: it runs a command that
// starts a child in a session of its own and stalls.
func TestRunContainedDeathHelper(t *testing.T) {
	pidFile := os.Getenv(containDeathHelperEnv)
	if pidFile == "" {
		t.Skip("helper process of TestRunContainedEndsTheTreeWhenTheGatewayDies")
	}
	_ = RunContained(exec.Command("/bin/sh", "-c", "setsid "+containChild+" &\nsleep 60", "sh", pidFile))
	os.Exit(1)
}

// A gateway that is SIGKILLed during a scan leaves nothing of it running.
func TestRunContainedEndsTheTreeWhenTheGatewayDies(t *testing.T) {
	requireContainTools(t)
	if os.Getenv(containDeathHelperEnv) != "" {
		t.Skip("running as the helper")
	}
	pidFile := filepath.Join(t.TempDir(), "escaped.pid")
	helper := exec.Command(os.Args[0], "-test.run=^TestRunContainedDeathHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), containDeathHelperEnv+"="+pidFile)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	pid := readContainPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	_ = helper.Process.Kill()
	_ = helper.Wait()
	for deadline := time.Now().Add(5 * time.Second); helperRunning(pid); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("descendant %d outlived the gateway that ran it", pid)
		}
	}
}

// The supervisor reports the command's own result and hides its marker.
func TestRunContainedKeepsTheCommandResult(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{"exit 0", 0},
		{"exit 3", 3},
		{"kill -TERM $$", 128 + int(syscall.SIGTERM)},
		{`[ -z "${` + containSupervisorEnv + `+x}" ] || exit 9`, 0},
	} {
		for name, run := range containRunners {
			err := run(CommandContext(context.Background(), "/bin/sh", "-c", tc.script))
			got := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				got = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("%s %q: %v", name, tc.script, err)
			}
			if got != tc.want {
				t.Fatalf("%s %q exited %d, want %d", name, tc.script, got, tc.want)
			}
		}
	}
	for name, run := range containRunners {
		if err := run(CommandContext(context.Background(), filepath.Join(t.TempDir(), "missing"))); err == nil {
			t.Fatalf("%s: a command that cannot start passed", name)
		}
	}
}

func readContainPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && convErr == nil {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("command never wrote %s: %v", path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
