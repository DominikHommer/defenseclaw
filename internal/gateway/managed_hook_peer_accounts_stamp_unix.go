// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// managedHookPeerListedStampInterval bounds the age of a listed account
// database stamp that a hook request reads: a request never waits for the
// listing, which runs in the background at most once per interval while
// requests come in. Explain lists at once (managedHookPeerAccountsRefresh).
const managedHookPeerListedStampInterval = 2 * time.Second

// managedHookPeerListTimeout bounds one listing of the local accounts.
const managedHookPeerListTimeout = 5 * time.Second

// managedHookPeerAccountsSource is where managedHookPeerAccountsStamp comes
// from. The account database file (stat) is the cheap source, but on macOS
// only root can read the dslocal users directory, and the managed gateway
// runs as _defenseclaw: there the stamp is a digest of the local accounts
// as Open Directory lists them to any account (list). Without it the stamp
// was always "" there, and only the home TTL applied (GAP-0669).
type managedHookPeerAccountsSource struct {
	stat func() string          // "" when unreadable
	list func() (string, error) // nil where the file is always readable
	now  func() time.Time

	mu         sync.Mutex
	listed     string
	listedAt   time.Time
	listedSeq  uint64 // the listing that set listed
	nextSeq    uint64
	refreshing bool
}

func newManagedHookPeerAccountsSource() *managedHookPeerAccountsSource {
	source := &managedHookPeerAccountsSource{stat: statLocalAccountsStamp, now: time.Now}
	if runtime.GOOS == "darwin" {
		source.list = listLocalAccountsStamp
	}
	return source
}

var managedHookPeerAccounts = newManagedHookPeerAccountsSource()

// get returns the stamp a request reads: the file's, else the last listed
// one, starting a listing in the background when it is older than the
// interval. "" until the first listing ends, or when neither source works.
func (s *managedHookPeerAccountsSource) get() string {
	if stamp := s.stat(); stamp != "" {
		return stamp
	}
	if s.list == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.refreshing && (s.listedAt.IsZero() || s.now().Sub(s.listedAt) >= managedHookPeerListedStampInterval) {
		s.refreshing = true
		seq := s.startLocked()
		go s.listInto(seq, true)
	}
	return s.listed
}

// refresh lists the local accounts now, when the file stamp is unreadable,
// so the next get returns the stamp of the account database as it is.
func (s *managedHookPeerAccountsSource) refresh() {
	if s.list == nil || s.stat() != "" {
		return
	}
	s.mu.Lock()
	seq := s.startLocked()
	s.mu.Unlock()
	s.listInto(seq, false)
}

func (s *managedHookPeerAccountsSource) startLocked() uint64 {
	s.nextSeq++
	return s.nextSeq
}

// listInto stores the stamp of listing seq unless a later listing already
// stored its own: a slow background listing started before an account
// change must not put back the stamp from before it.
func (s *managedHookPeerAccountsSource) listInto(seq uint64, background bool) {
	stamp, err := s.list()
	if err != nil {
		stamp = ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if background {
		s.refreshing = false
	}
	if seq > s.listedSeq {
		s.listed, s.listedAt, s.listedSeq = stamp, s.now(), seq
	}
}

// statLocalAccountsStamp is the stamp of the account database file:
// useradd, userdel and usermod replace /etc/passwd, and macOS keeps a local
// account's record in the dslocal users directory. "" when it cannot be
// read.
func statLocalAccountsStamp() string {
	path := "/etc/passwd"
	if runtime.GOOS == "darwin" {
		path = "/var/db/dslocal/nodes/Default/users"
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	stamp := strconv.FormatInt(info.ModTime().UnixNano(), 10) + "/" + strconv.FormatInt(info.Size(), 10)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp += "/" + strconv.FormatUint(uint64(st.Ino), 10)
	}
	return stamp
}

// listLocalAccountsStamp is the stamp of the local accounts as the platform
// lists them (dscl on macOS): any change of a name or uid changes it.
func listLocalAccountsStamp() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), managedHookPeerListTimeout)
	defer cancel()
	accounts, err := unixidentity.LocalAccounts(ctx)
	if err != nil {
		return "", err
	}
	return localAccountsDigest(accounts)
}

var errNoLocalAccounts = errors.New("the local account list is empty")

// localAccountsDigest is the order-independent digest of name to uid.
func localAccountsDigest(accounts map[string]int) (string, error) {
	if len(accounts) == 0 {
		return "", errNoLocalAccounts
	}
	names := make([]string, 0, len(accounts))
	for name := range accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	sum := sha256.New()
	for _, name := range names {
		fmt.Fprintf(sum, "%s\x00%d\n", name, accounts[name])
	}
	return "listed/" + hex.EncodeToString(sum.Sum(nil)[:16]), nil
}
