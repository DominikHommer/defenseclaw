// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// A per-user foreign-cleanup worker runs as the user and cannot open the
// machine's foreign-hook cleanup fence. It asks the guardian for it over two
// pipes, right before its first removal for a connector, and hands that
// connector's removals back once its cleanup ends: the guardian commits them
// to the removal ledger and releases the fence before the worker goes on.
// A scan that finds nothing to remove, and every other task of the worker
// (VS Code Local files, leftover and personal Claude Code targets, block
// records), never holds the fence, so neither the gateway's exchanges nor
// another account's cleanup waits on them.
const (
	// enterpriseHookWorkerFenceGrantFD carries the guardian's replies.
	enterpriseHookWorkerFenceGrantFD = 3
	// enterpriseHookWorkerFenceAskFD carries the worker's requests.
	enterpriseHookWorkerFenceAskFD = 4
	// enterpriseHookWorkerFenceMessageLimit bounds one message: a commit
	// names at most 32 paths of at most 512 bytes (boundedStrings).
	enterpriseHookWorkerFenceMessageLimit = 64 << 10

	enterpriseHookWorkerFenceOpLock   = "lock"
	enterpriseHookWorkerFenceOpCommit = "commit"
)

type enterpriseHookWorkerFenceAsk struct {
	Op        string   `json:"op"`
	Connector string   `json:"connector"`
	Removed   []string `json:"removed,omitempty"`
}

type enterpriseHookWorkerFenceReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// enterpriseForeignHookFenceSession is the guardian's side of one worker's
// fence requests. Each connector of the job may take the fence once, and
// its commit records that connector's removals and releases the fence.
type enterpriseForeignHookFenceSession struct {
	record  func(connector string, removed []string)
	allowed map[string]bool

	mu        sync.Mutex
	unlock    func()
	locked    map[string]bool
	committed map[string]bool
}

func newEnterpriseForeignHookFenceSession(cleanups []enterpriseHookWorkerForeignCleanup, record func(connector string, removed []string)) *enterpriseForeignHookFenceSession {
	allowed := map[string]bool{}
	for _, cleanup := range cleanups {
		if name := enterpriseHookWorkerFenceConnector(cleanup.Connector); name != "" {
			allowed[name] = true
		}
	}
	return &enterpriseForeignHookFenceSession{record: record, allowed: allowed, locked: map[string]bool{}, committed: map[string]bool{}}
}

func enterpriseHookWorkerFenceConnector(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// lock takes the cleanup fence for connector's first removal, within ctx
// (the worker's own timeout) for this guardian's turn.
func (s *enterpriseForeignHookFenceSession) lock(ctx context.Context, connector string) error {
	name := enterpriseHookWorkerFenceConnector(connector)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !s.allowed[name]:
		return fmt.Errorf("connector %q is not part of this cleanup", boundedString(connector, 64))
	case s.locked[name]:
		return fmt.Errorf("the %s cleanup already took the fence", name)
	}
	if s.unlock == nil {
		unlock, err := acquireEnterpriseForeignHookCleanupFence(ctx)
		if err != nil {
			return err
		}
		s.unlock = unlock
	}
	s.locked[name] = true
	return nil
}

// commit records connector's removals in the ledger, then releases the
// fence.
func (s *enterpriseForeignHookFenceSession) commit(connector string, removed []string) error {
	name := enterpriseHookWorkerFenceConnector(connector)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.locked[name] || s.committed[name] {
		return fmt.Errorf("the %s cleanup does not hold the fence", boundedString(name, 64))
	}
	s.committed[name] = true
	s.record(name, boundedStrings(removed, 32))
	s.releaseLocked()
	return nil
}

// isCommitted reports whether connector's removals were already recorded.
func (s *enterpriseForeignHookFenceSession) isCommitted(connector string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.committed[enterpriseHookWorkerFenceConnector(connector)]
}

// release lets go of a fence the worker took and never committed (it
// failed or timed out after its lock). The caller records what the
// worker's response reports first.
func (s *enterpriseForeignHookFenceSession) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseLocked()
}

func (s *enterpriseForeignHookFenceSession) releaseLocked() {
	if s.unlock != nil {
		s.unlock()
		s.unlock = nil
	}
}

// serve answers the worker's requests read from asks until the pipe ends,
// a request is malformed or ctx is done.
func (s *enterpriseForeignHookFenceSession) serve(ctx context.Context, asks io.Reader, replies io.Writer) {
	scanner := bufio.NewScanner(asks)
	scanner.Buffer(make([]byte, 0, 4096), enterpriseHookWorkerFenceMessageLimit)
	for scanner.Scan() {
		var ask enterpriseHookWorkerFenceAsk
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&ask); err != nil {
			_ = writeEnterpriseHookWorkerFenceMessage(replies, enterpriseHookWorkerFenceReply{Error: "malformed fence request"})
			return
		}
		var err error
		switch ask.Op {
		case enterpriseHookWorkerFenceOpLock:
			err = s.lock(ctx, ask.Connector)
		case enterpriseHookWorkerFenceOpCommit:
			err = s.commit(ask.Connector, ask.Removed)
		default:
			err = fmt.Errorf("unknown fence request %q", boundedString(ask.Op, 32))
		}
		reply := enterpriseHookWorkerFenceReply{OK: err == nil}
		if err != nil {
			reply.Error = boundedString(err.Error(), 512)
		}
		if writeEnterpriseHookWorkerFenceMessage(replies, reply) != nil {
			return
		}
	}
}

func writeEnterpriseHookWorkerFenceMessage(w io.Writer, message any) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// attachEnterpriseHookWorkerFence gives cmd the fence pipes when request
// carries a fence session and serves them until the returned function is
// called, after the worker has ended. That function waits for a request in
// progress (a ledger commit) to finish.
func attachEnterpriseHookWorkerFence(ctx context.Context, cmd *exec.Cmd, request enterpriseHookWorkerRequest) (func(), error) {
	session := request.cleanupFence
	if session == nil {
		return func() {}, nil
	}
	grantRead, grantWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("foreign-hook cleanup fence pipe: %w", err)
	}
	askRead, askWrite, err := os.Pipe()
	if err != nil {
		_ = grantRead.Close()
		_ = grantWrite.Close()
		return nil, fmt.Errorf("foreign-hook cleanup fence pipe: %w", err)
	}
	// ExtraFiles[i] is the worker's descriptor 3+i.
	cmd.ExtraFiles = []*os.File{grantRead, askWrite}
	serveCtx, cancel := context.WithCancel(ctx)
	served := make(chan struct{})
	go func() {
		defer close(served)
		session.serve(serveCtx, askRead, grantWrite)
	}()
	return func() {
		cancel()
		_ = askRead.Close()
		<-served
		_ = grantWrite.Close()
		_ = grantRead.Close()
		_ = askWrite.Close()
	}, nil
}

// enterpriseHookWorkerCleanupFence is the worker's side: lock before the
// first removal of a connector, commit once its cleanup ends.
type enterpriseHookWorkerCleanupFence interface {
	lock(connector string) error
	commit(connector string, removed []string) error
}

type enterpriseHookWorkerFencePipe struct {
	replies *bufio.Scanner
	asks    io.Writer
}

// openEnterpriseHookWorkerFencePipe takes the fence pipes the guardian
// passed. They are kept from any process the worker starts.
func openEnterpriseHookWorkerFencePipe() (*enterpriseHookWorkerFencePipe, error) {
	files := make([]*os.File, 0, 2)
	for _, fd := range []int{enterpriseHookWorkerFenceGrantFD, enterpriseHookWorkerFenceAskFD} {
		file := os.NewFile(uintptr(fd), "foreign-hook-cleanup-fence")
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return nil, errors.New("the guardian passed no foreign-hook cleanup fence pipe")
		}
		syscall.CloseOnExec(fd)
		files = append(files, file)
	}
	replies := bufio.NewScanner(files[0])
	replies.Buffer(make([]byte, 0, 1024), enterpriseHookWorkerFenceMessageLimit)
	return &enterpriseHookWorkerFencePipe{replies: replies, asks: files[1]}, nil
}

func (p *enterpriseHookWorkerFencePipe) exchange(ask enterpriseHookWorkerFenceAsk) error {
	if err := writeEnterpriseHookWorkerFenceMessage(p.asks, ask); err != nil {
		return fmt.Errorf("foreign-hook cleanup fence: %w", err)
	}
	if !p.replies.Scan() {
		return errors.New("foreign-hook cleanup fence: the guardian did not answer")
	}
	var reply enterpriseHookWorkerFenceReply
	if err := json.Unmarshal(p.replies.Bytes(), &reply); err != nil {
		return fmt.Errorf("foreign-hook cleanup fence: %w", err)
	}
	if !reply.OK {
		return fmt.Errorf("foreign-hook cleanup fence: %s", firstNonEmpty(reply.Error, "refused"))
	}
	return nil
}

func (p *enterpriseHookWorkerFencePipe) lock(connector string) error {
	return p.exchange(enterpriseHookWorkerFenceAsk{Op: enterpriseHookWorkerFenceOpLock, Connector: connector})
}

func (p *enterpriseHookWorkerFencePipe) commit(connector string, removed []string) error {
	return p.exchange(enterpriseHookWorkerFenceAsk{Op: enterpriseHookWorkerFenceOpCommit, Connector: connector, Removed: removed})
}
