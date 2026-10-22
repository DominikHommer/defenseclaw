// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// ErrGatewayNotVerified is returned when the operating system does not show
// that a process is a DefenseClaw gateway of this account and this home.
var ErrGatewayNotVerified = errors.New("gateway not verified")

// errProcessOfAnotherAccount: the process does not run as this account.
var errProcessOfAnotherAccount = errors.New("runs as another account")

// maxProcessEnvironmentBytes bounds the environment read of another process.
const maxProcessEnvironmentBytes = 4 << 20

// ProveOwnGateway proves now, from the operating system alone, that process
// pid is the DefenseClaw gateway of this account that Daemon.Start launched
// for the DefenseClaw home home, so it may be sent that home's gateway
// credential. The process must run as this account (its real and effective
// uid on Linux and macOS, the user SID of its token on Windows), from this
// DefenseClaw binary (the executable Daemon.Start launches the gateway
// from), and with the environment Daemon.Start gives the gateway of home:
// one daemon marker and one data directory, home. The kernel keeps that
// environment from the program's start (/proc/<pid>/environ on Linux,
// kern.procargs2 on macOS, the process parameters on Windows), and only this
// account and the administrator can read it. No record is read. A PID
// record, or any other file, names a process; only the kernel shows whose it
// is, what it runs and which home it was started for, and a copied, stale or
// crafted record named another home's or another account's gateway. It
// returns pid's kernel start identity, which must be the same before and
// after the checks, so a PID the OS gave to another process in between
// fails. Every failure wraps ErrGatewayNotVerified.
func ProveOwnGateway(pid int, home string) (string, error) {
	expected, err := os.Executable()
	if err != nil || expected == "" {
		return "", fmt.Errorf("%w: this DefenseClaw binary's path is unknown: %v", ErrGatewayNotVerified, err)
	}
	return proveOwnGateway(pid, expected, home)
}

func proveOwnGateway(pid int, expected, home string) (string, error) {
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
	if err := gatewayStartedForHome(pid, home); err != nil {
		return "", err
	}
	after, err := processStartIdentity(pid)
	if err != nil || after != before {
		return "", fmt.Errorf("%w: PID %d exited during the check", ErrGatewayNotVerified, pid)
	}
	return before, nil
}

// gatewayStartedForHome proves from the kernel's copy of pid's environment
// that Daemon.Start launched it as the gateway of home: exactly one
// EnvDaemon=1 and exactly one EnvDataDir, naming home. Every release since
// 0.8 starts its gateway so (childEnv), and .env cannot set either variable.
func gatewayStartedForHome(pid int, home string) error {
	environment, err := processEnvironment(pid)
	if err != nil {
		return fmt.Errorf("%w: the environment of PID %d is unreadable (%v); "+
			"read a gateway started from an elevated shell from an elevated shell", ErrGatewayNotVerified, pid, err)
	}
	var markers, dataDirs []string
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		switch {
		case !ok:
		case environmentKeyIs(key, EnvDaemon):
			markers = append(markers, value)
		case environmentKeyIs(key, EnvDataDir):
			dataDirs = append(dataDirs, value)
		}
	}
	if len(markers) != 1 || markers[0] != "1" || len(dataDirs) != 1 || strings.TrimSpace(dataDirs[0]) == "" {
		return fmt.Errorf("%w: PID %d was not started by `defenseclaw-gateway start`; "+
			"restart the gateway with `defenseclaw-gateway restart`", ErrGatewayNotVerified, pid)
	}
	if strings.TrimSpace(home) == "" || !sameHomePath(dataDirs[0], home) {
		return fmt.Errorf("%w: PID %d is the gateway of another DefenseClaw home; "+
			"start this home's gateway with `defenseclaw-gateway start`", ErrGatewayNotVerified, pid)
	}
	return nil
}

// sameHomePath reports whether the data directory a gateway was started for
// is home: the same string Daemon.Start was given, or the same directory.
func sameHomePath(started, home string) bool {
	return started == home || pathidentity.Same(started, home)
}

// environmentKeyIs compares environment variable names as the operating
// system does: without case on Windows.
func environmentKeyIs(key, name string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(key, name)
	}
	return key == name
}

// splitNULStrings splits NUL-terminated strings, dropping empty ones.
func splitNULStrings(data []byte) []string {
	var out []string
	for _, entry := range bytes.Split(data, []byte{0}) {
		if len(entry) > 0 {
			out = append(out, string(entry))
		}
	}
	return out
}

// procArgs2Environment is the environment in a macOS kern.procargs2 record:
// a 4-byte argument count, the executable path, NUL padding, the arguments
// and then the environment, each string ending in NUL. An empty string ends
// the environment.
func procArgs2Environment(data []byte) ([]string, error) {
	if len(data) < 4 || len(data) > maxProcessEnvironmentBytes {
		return nil, fmt.Errorf("kern.procargs2 has %d bytes", len(data))
	}
	argc := int(binary.LittleEndian.Uint32(data[:4]))
	rest := data[4:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 || argc <= 0 || argc > len(rest) {
		return nil, errors.New("kern.procargs2 does not parse")
	}
	rest = bytes.TrimLeft(rest[end:], "\x00")
	for index := 0; index < argc; index++ {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, errors.New("kern.procargs2 arguments are truncated")
		}
		rest = rest[end+1:]
	}
	var environment []string
	for {
		end := bytes.IndexByte(rest, 0)
		if end <= 0 {
			// The end of the environment, or a last string the record cut.
			return environment, nil
		}
		environment = append(environment, string(rest[:end]))
		rest = rest[end+1:]
	}
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
