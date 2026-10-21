//go:build !windows && !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"os/exec"
	"syscall"
)

// trustedCommandSysProcAttr puts a directory tool in its own process group.
// There is no parent-death signal here; a managed macOS hook looks its
// account up in process (os/user through libSystem) and starts no tool.
func trustedCommandSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func runBoundToParent(cmd *exec.Cmd) error { return cmd.Run() }
