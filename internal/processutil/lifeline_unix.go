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

//go:build linux || darwin

package processutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// lifelineWait bounds the wait for the lifeline to close once the command's
// group is gone; tests shorten it.
var lifelineWait = time.Second

// runTreeWithLifeline is RunTree plus a lifeline: the write end of a pipe
// that the command and every descendant inherit, which only this process
// reads. After RunTree has killed the command's process group, the lifeline
// closes only if nothing that inherited it still runs; a descendant that
// left the group (setsid, setpgid) and kept it fails the run with
// ErrNotContained. A descendant that also closed its inherited descriptors
// is not seen.
func runTreeWithLifeline(cmd *exec.Cmd) error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("%w: lifeline: %v", ErrNotContained, err)
	}
	defer r.Close()
	defer w.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, w)
	if err := runTreeAfterStart(cmd, func() { _ = w.Close() }); err != nil {
		return err
	}
	if !lifelineClosed(r, lifelineWait) {
		return fmt.Errorf("%w: %s left a process outside its group", ErrNotContained, cmd.Path)
	}
	return nil
}

// lifelineClosed reports whether every write end of r is closed within wait.
func lifelineClosed(r *os.File, wait time.Duration) bool {
	if err := r.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return false
	}
	buf := make([]byte, 64)
	for {
		_, err := r.Read(buf)
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return false
		}
	}
}
