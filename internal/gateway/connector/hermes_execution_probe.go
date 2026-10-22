// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const hermesExecutionProbeResponse = "defenseclaw-execution-probe-ok\n"

// hermesRegisteredCommandExecutable probes only the target Setup computed.
// ownedHooksPresentInConfig has already read back the exact agent registration,
// so an edited command cannot make Verify execute an arbitrary program.
func hermesRegisteredCommandExecutable(opts SetupOpts, hookCommand string) bool {
	target := hermesHookExecutablePath(hookCommand, opts.HookExecutable)
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	args := []string{"--defenseclaw-execution-probe"}
	if runtime.GOOS == "windows" {
		// Probe the registered native command through its launcher and hook
		// runtime. A disabled launcher can return success without delegating;
		// only the active hook runtime emits the proof response.
		if !strings.EqualFold(filepath.Ext(target), ".exe") ||
			windowsHermesDirectHookCommand(opts.HookExecutable) != hookCommand {
			return false
		}
		args = []string{"hook", "--connector", "hermes", "--defenseclaw-execution-probe"}
	} else if info.Mode().Perm()&0o111 == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, target, args...)
	output, err := cmd.Output()
	return err == nil && string(output) == hermesExecutionProbeResponse
}
