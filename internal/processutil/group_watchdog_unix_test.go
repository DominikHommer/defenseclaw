//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package processutil

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The watchdog keeps its group's ID while it may still signal it. When the
// gateway dies after the scanner leader exited, init reaps the orphaned
// leader before the watchdog's kill. A group with no member left can be
// reused, and the kill would then reach an unrelated group (W4b2 scanner,
// loop round 1).
func TestGroupWatchdogKeepsTheGroupAfterItsLeaderIsReaped(t *testing.T) {
	leader := exec.Command("/bin/sleep", "60")
	leader.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := leader.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := leader.Process.Pid
	stop, err := startGroupWatchdog(pgid)
	if err != nil {
		_ = leader.Process.Kill()
		_ = leader.Wait()
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			stop()
		}
	})
	// The scanner ends and is reaped while the watchdog still runs, as when
	// its new parent reaps it after the gateway died.
	_ = leader.Process.Kill()
	_ = leader.Wait()
	if err := syscall.Kill(-pgid, 0); err != nil {
		t.Fatalf("group %d has no member once its leader is reaped (%v): its ID can be reused before the watchdog signals it", pgid, err)
	}
	// The watchdog's kill reaches whatever is still in the group.
	helper := exec.Command("/bin/sleep", "60")
	helper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: pgid}
	if err := helper.Start(); err != nil {
		t.Fatalf("join group %d after its leader was reaped: %v", pgid, err)
	}
	done := make(chan error, 1)
	go func() { done <- helper.Wait() }()
	stop()
	stopped = true
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = helper.Process.Kill()
		<-done
		t.Fatal("the watchdog's kill did not reach its group")
	}
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("group %d after the watchdog's kill: %v, want ESRCH", pgid, err)
	}
}

// A watchdog for no group, or for init's, signals nothing.
func TestGroupWatchdogRefusesANonGroup(t *testing.T) {
	for _, pgid := range []int{-1, 0, 1} {
		if stop, err := startGroupWatchdog(pgid); err == nil {
			stop()
			t.Fatalf("startGroupWatchdog(%d) started a watchdog", pgid)
		}
	}
}
