// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

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
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var (
	enterpriseSetupArmUninstallRecovery = armStandaloneUninstallRecovery
	setupRecoveryWaitForParent          = waitForStandaloneSetupParent
	setupRecoveryPending                = standaloneUninstallTransactionPending
	setupRecoveryReplay                 = replayStandaloneSetupTransaction
)

// armStandaloneUninstallRecovery runs before the lifecycle worker. A killed
// Setup must not strand a transaction after the worker removed managed hooks.
func armStandaloneUninstallRecovery() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	child := exec.Command(executable, "--internal-recover-after-parent", strconv.Itoa(os.Getpid()))
	child.Dir = filepath.Dir(executable)
	child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: standaloneSetupRecoveryCreationFlags()}
	if err := child.Start(); err != nil {
		return err
	}
	return child.Process.Release()
}

func standaloneSetupRecoveryCreationFlags() uint32 {
	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	if errors.Is(err, windows.ERROR_INVALID_HANDLE) ||
		(err == nil && info.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK != 0) {
		flags |= windows.CREATE_BREAKAWAY_FROM_JOB
	}
	return flags
}

func runStandaloneSetupRecoveryWatchdog(parentArgument string, _, stderr io.Writer) int {
	parentPID, err := strconv.Atoi(parentArgument)
	if err != nil || parentPID <= 0 || parentPID == os.Getpid() {
		return enterpriseInvalidArgsExitCode
	}
	if err := setupRecoveryWaitForParent(parentPID); err != nil {
		fmt.Fprintln(stderr, err)
		return enterpriseFailureExitCode
	}
	pending, err := setupRecoveryPending()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return enterpriseFailureExitCode
	}
	if !pending {
		return 0
	}
	if err := setupRecoveryReplay(); err != nil {
		fmt.Fprintln(stderr, err)
		return enterpriseFailureExitCode
	}
	return 0
}

func waitForStandaloneSetupParent(pid int) error {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil // Parent already exited before the watcher opened it.
	}
	if err != nil {
		return fmt.Errorf("open uninstall Setup parent: %w", err)
	}
	defer windows.CloseHandle(handle) //nolint:errcheck -- process is already exiting.
	result, err := windows.WaitForSingleObject(handle, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("wait for uninstall Setup parent: %w", err)
	}
	if result != uint32(windows.WAIT_OBJECT_0) {
		return fmt.Errorf("wait for uninstall Setup parent: unexpected result %d", result)
	}
	return nil
}

func standaloneUninstallTransactionPending() (bool, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return false, err
	}
	path := filepath.Join(layout.LifecycleDir, "pending.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := managed.ValidateTrustedFilePath(path, "standalone pending transaction"); err != nil {
		return false, err
	}
	return true, nil
}

func replayStandaloneSetupTransaction() error {
	opts := enterpriseSetupOptions{Action: "recover", Standalone: true, JSON: true, LifecycleTimeout: 30 * time.Minute}
	var output bytes.Buffer
	code, err := executeEnterpriseSetup(context.Background(), opts, &output, io.Discard)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("uninstall transaction recovery exited %d", code)
	}
	var report enterprisestatus.Result
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		return fmt.Errorf("decode uninstall transaction recovery: %w", err)
	}
	return proveStandaloneUninstallRecovery(report)
}

func proveStandaloneUninstallRecovery(report enterprisestatus.Result) error {
	if report.SchemaVersion != 2 || report.Action != "recover" || report.Profile != managed.ProfileStandalone ||
		!report.OK || !report.Installed || report.TransactionPending || report.ExitCode != 0 {
		return errors.New("uninstall recovery did not prove a settled enforcing installation")
	}
	gateway, guardian := false, false
	for _, service := range report.Services {
		if service.Kind == "gateway" && service.State == "running" {
			gateway = true
		}
		if service.Kind == "guardian" && service.State == "running" {
			guardian = true
		}
	}
	if !gateway || !guardian {
		return errors.New("uninstall recovery left a managed service stopped")
	}
	return nil
}
