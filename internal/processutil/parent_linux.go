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
	"os/exec"
	"runtime"
	"syscall"
)

// runWithParent runs cmd so that the kernel kills it when this process
// dies. Linux sends the parent-death signal when the thread that started the
// child ends, not the process, so cmd runs on a thread locked to this
// goroutine: the runtime cannot end that thread while the child still runs.
func runWithParent(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return cmd.Run()
}
