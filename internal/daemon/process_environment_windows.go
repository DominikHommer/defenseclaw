// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsProcessBasicInformation is PROCESS_BASIC_INFORMATION with the PEB
// address kept as a number: it is an address in the other process.
type windowsProcessBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// processEnvironment is the environment block of pid, read from its process
// parameters (PEB). Windows grants PROCESS_VM_READ on a process to its own
// account at the same or a higher integrity level, not to another account
// and not up to an elevated process from a standard shell. Every length and
// address comes from the other process and is bounds-checked.
func processEnvironment(pid int) ([]string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(process)
	var info windowsProcessBasicInformation
	var returned uint32
	if err := windows.NtQueryInformationProcess(process, windows.ProcessBasicInformation,
		unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), &returned); err != nil {
		return nil, err
	}
	if info.PebBaseAddress == 0 {
		return nil, errors.New("the process has no readable PEB")
	}
	var parameters uintptr
	if err := readWindowsProcessMemory(process, info.PebBaseAddress+unsafe.Offsetof(windows.PEB{}.ProcessParameters),
		unsafe.Pointer(&parameters), unsafe.Sizeof(parameters)); err != nil {
		return nil, err
	}
	if parameters == 0 {
		return nil, errors.New("the process has no readable parameter block")
	}
	var block, size uintptr
	if err := readWindowsProcessMemory(process, parameters+unsafe.Offsetof(windows.RTL_USER_PROCESS_PARAMETERS{}.Environment),
		unsafe.Pointer(&block), unsafe.Sizeof(block)); err != nil {
		return nil, err
	}
	if err := readWindowsProcessMemory(process, parameters+unsafe.Offsetof(windows.RTL_USER_PROCESS_PARAMETERS{}.EnvironmentSize),
		unsafe.Pointer(&size), unsafe.Sizeof(size)); err != nil {
		return nil, err
	}
	if block == 0 || size < 2 {
		return nil, errors.New("the process has no environment block")
	}
	if size > maxProcessEnvironmentBytes {
		return nil, fmt.Errorf("the environment of PID %d exceeds %d bytes", pid, maxProcessEnvironmentBytes)
	}
	units := make([]uint16, size/2)
	if err := readWindowsProcessMemory(process, block, unsafe.Pointer(&units[0]), uintptr(len(units))*2); err != nil {
		return nil, err
	}
	var environment []string
	start := 0
	for index, unit := range units {
		if unit != 0 {
			continue
		}
		if index == start {
			break // the empty string that ends the block
		}
		environment = append(environment, windows.UTF16ToString(units[start:index]))
		start = index + 1
	}
	return environment, nil
}

func readWindowsProcessMemory(process windows.Handle, address uintptr, into unsafe.Pointer, size uintptr) error {
	var read uintptr
	if err := windows.ReadProcessMemory(process, address, (*byte)(into), size, &read); err != nil {
		return err
	}
	if read != size {
		return fmt.Errorf("short read of the process memory at %#x (%d of %d bytes)", address, read, size)
	}
	return nil
}
