// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sandboxcli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Attached sessions. Several sessions can attach to one sandbox (a `run`
// that resumes it, a `connect`, a `connect --shell`), and they share it:
// one session's end must not stop the sandbox, or undo the folder, under
// another's harness. Each session holds a lease while its harness or shell
// runs: a file in the sandbox's CLI state directory that the session's
// process keeps flock'ed, so the lease of a session that dies goes with its
// process.

const leaseSuffix = ".lease"
const sessionGateFile = ".gate"

func (a *App) sessionsDir(name string) (string, error) {
	dir, err := a.cliStateDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sessions"), nil
}

// sessionGate serializes lease creation and a session's final stop/delete.
// A reconnect starting during cleanup waits for that decision, then sees
// the sandbox's new state instead of being stopped underneath its harness.
func (a *App) sessionGate(name string) (release func(), err error) {
	dir, err := a.sessionsDir(name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, sessionGateFile), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

// holdSession records a harness or shell until release. Failure refuses the
// attach: without the lease another terminal cannot know to leave it running.
func (a *App) holdSession(name string) (release func(), err error) {
	unlock, err := a.sessionGate(name)
	if err != nil {
		return nil, fmt.Errorf("cannot record the session with %s: %w; run `%s status %s`, then retry the connect", name, err, CommandName, name)
	}
	defer unlock()
	dir, _ := a.sessionsDir(name)
	var id [6]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("cannot record the session with %s: %w", name, err)
	}
	path := filepath.Join(dir, strconv.Itoa(os.Getpid())+"-"+hex.EncodeToString(id[:])+leaseSuffix)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot record the session with %s: %w", name, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("cannot lock the session with %s: %w", name, err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			// Removed first: a count that opens it before the close sees it
			// held, one after finds nothing.
			_ = os.Remove(path)
			_ = f.Close()
		})
	}, nil
}

// attachedSessions counts the sessions whose harness or shell runs in
// sandbox name now (on this machine, with this data dir). A lease whose
// process is gone is removed.
func (a *App) attachedSessions(name string) int {
	n, _ := a.attachedSessionsChecked(name)
	return n
}

func (a *App) attachedSessionsChecked(name string) (int, error) {
	dir, err := a.sessionsDir(name)
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), leaseSuffix) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return 0, err
		}
		switch err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); {
		case errors.Is(err, syscall.EWOULDBLOCK):
			n++
		case err == nil:
			// Its process is gone.
			_ = os.Remove(path)
		case err != nil:
			_ = f.Close()
			return 0, err
		}
		_ = f.Close()
	}
	return n, nil
}
