// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// ErrGatewayNotVerified is returned when the operating system does not show
// that a process is a DefenseClaw gateway of this account.
var ErrGatewayNotVerified = errors.New("gateway not verified")

// errProcessOfAnotherAccount: the process does not run as this account.
var errProcessOfAnotherAccount = errors.New("runs as another account")

// ProveOwnGateway proves now, from the operating system alone, that process
// pid is a DefenseClaw gateway of this account, so it may be sent this
// account's gateway credential. The process must run as this account (its
// real and effective uid on Linux and macOS, the user SID of its token on
// Windows) and from this DefenseClaw binary: the executable Daemon.Start
// launches the gateway from. No record is read. A PID record, or any other
// file, names a process; only the kernel shows whose it is and what it runs,
// and a copied, stale or crafted record named another home's or another
// account's gateway. It returns pid's kernel start identity, which must be
// the same before and after the checks, so a PID the OS gave to another
// process in between fails. Every failure wraps ErrGatewayNotVerified.
func ProveOwnGateway(pid int) (string, error) {
	expected, err := os.Executable()
	if err != nil || expected == "" {
		return "", fmt.Errorf("%w: this DefenseClaw binary's path is unknown: %v", ErrGatewayNotVerified, err)
	}
	return proveOwnGateway(pid, expected)
}

func proveOwnGateway(pid int, expected string) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("%w: no gateway process", ErrGatewayNotVerified)
	}
	before, err := processStartIdentity(pid)
	if err != nil || before == "" {
		return "", fmt.Errorf("%w: the start identity of PID %d is unreadable", ErrGatewayNotVerified, pid)
	}
	if err := processRunsAsCaller(pid); err != nil {
		if errors.Is(err, errProcessOfAnotherAccount) {
			// No PID: another account's process is not this account's to see.
			return "", fmt.Errorf("%w: the process holding the gateway listener runs as another account", ErrGatewayNotVerified)
		}
		return "", fmt.Errorf("%w: the owner of PID %d is unreadable: %v", ErrGatewayNotVerified, pid, err)
	}
	live, err := processExecutable(pid)
	if err != nil || live == "" {
		return "", fmt.Errorf("%w: the executable of PID %d is unreadable", ErrGatewayNotVerified, pid)
	}
	if !gatewayExecutableIs(live, expected) {
		return "", fmt.Errorf("%w: PID %d runs %s, not this DefenseClaw binary %s "+
			"(if the gateway was upgraded or moved while it ran, restart it with `defenseclaw-gateway restart`)",
			ErrGatewayNotVerified, pid, live, expected)
	}
	after, err := processStartIdentity(pid)
	if err != nil || after != before {
		return "", fmt.Errorf("%w: PID %d exited during the check", ErrGatewayNotVerified, pid)
	}
	return before, nil
}

// processExecutable is the path the kernel reports for the program pid runs.
func processExecutable(pid int) (string, error) {
	switch runtime.GOOS {
	case "linux":
		return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	case "darwin":
		return processExecutableDarwin(pid)
	case "windows":
		return processExecutableWindows(pid)
	default:
		return "", fmt.Errorf("process inspection is not supported on %s", runtime.GOOS)
	}
}

// gatewayExecutableIs reports whether live, the program a process runs, is
// expected. On Linux a gateway whose file an in-place upgrade replaced, or a
// source install moved into its custody, while it ran shows the same path
// plus " (deleted)", or the custody copy: still this binary's gateway.
func gatewayExecutableIs(live, expected string) bool {
	if runtime.GOOS == "linux" &&
		(live == expected || live == expected+" (deleted)" || IsRetiredInstallCopy(expected, live)) {
		return true
	}
	return pathidentity.Same(live, expected)
}
