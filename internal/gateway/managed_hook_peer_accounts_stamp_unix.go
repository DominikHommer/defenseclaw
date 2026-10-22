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
// from. On Linux it is the stat of /etc/passwd, which useradd, userdel and
// usermod replace. On macOS only root can read the dslocal users directory,
// and the managed gateway runs as _defenseclaw, so the stamp is a digest of
// the local accounts as Open Directory lists them to any account (list):
// name, uid, the record's GeneratedUID, home and primary group (GAP-0669).
// Open Directory gives every account it creates a new GeneratedUID, so an
// account deleted and created again under the same name and uid changes the
// stamp, and its record (record) tells it from the account whose facts were
// cached.
type managedHookPeerAccountsSource struct {
	stat func() string                          // nil, or "" when unreadable
	list func() (managedHookPeerListing, error) // nil where the file is the source
	now  func() time.Time

	mu         sync.Mutex
	listed     managedHookPeerListing
	listedAt   time.Time
	listedSeq  uint64 // the listing that set listed
	nextSeq    uint64
	refreshing bool
}

// managedHookPeerListing is one listing of the local accounts: its stamp
// and each account's record by name.
type managedHookPeerListing struct {
	stamp   string
	records map[string]string
}

func newManagedHookPeerAccountsSource() *managedHookPeerAccountsSource {
	if runtime.GOOS == "darwin" {
		return &managedHookPeerAccountsSource{list: listLocalAccountsStamp, now: time.Now}
	}
	return &managedHookPeerAccountsSource{stat: statLocalAccountsStamp, now: time.Now}
}

var managedHookPeerAccounts = newManagedHookPeerAccountsSource()

// fileStamped reports whether the stamp comes from the account database
// file now.
func (s *managedHookPeerAccountsSource) fileStamped() (string, bool) {
	if s.stat == nil {
		return "", false
	}
	stamp := s.stat()
	return stamp, stamp != ""
}

// get returns the stamp a request reads: the file's, else the last listed
// one, starting a listing in the background when it is older than the
// interval. "" until the first listing ends, or when neither source works.
func (s *managedHookPeerAccountsSource) get() string {
	if stamp, ok := s.fileStamped(); ok {
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
	return s.listed.stamp
}

// record returns the listed record of the local account name: "" where the
// stamp comes from the file, before the first listing ends, after a failed
// one, and for an account the local node does not hold.
func (s *managedHookPeerAccountsSource) record(name string) string {
	if s.list == nil {
		return ""
	}
	if _, ok := s.fileStamped(); ok {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listed.records[name]
}

// refresh lists the local accounts now, when the file stamp is unreadable,
// so the next get returns the stamp of the account database as it is.
func (s *managedHookPeerAccountsSource) refresh() {
	if s.list == nil {
		return
	}
	if _, ok := s.fileStamped(); ok {
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

// listInto stores the listing seq unless a later listing already stored
// its own: a slow background listing started before an account change must
// not put back the stamp from before it.
func (s *managedHookPeerAccountsSource) listInto(seq uint64, background bool) {
	listing, err := s.list()
	if err != nil {
		listing = managedHookPeerListing{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if background {
		s.refreshing = false
	}
	if seq > s.listedSeq {
		s.listed, s.listedAt, s.listedSeq = listing, s.now(), seq
	}
}

// statLocalAccountsStamp is the stamp of /etc/passwd, which useradd,
// userdel and usermod replace. "" when it cannot be read.
func statLocalAccountsStamp() string {
	info, err := os.Stat("/etc/passwd")
	if err != nil {
		return ""
	}
	stamp := strconv.FormatInt(info.ModTime().UnixNano(), 10) + "/" + strconv.FormatInt(info.Size(), 10)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp += "/" + strconv.FormatUint(uint64(st.Ino), 10)
	}
	return stamp
}

// listLocalAccountsStamp lists the local accounts with their records
// (dscl on macOS).
func listLocalAccountsStamp() (managedHookPeerListing, error) {
	ctx, cancel := context.WithTimeout(context.Background(), managedHookPeerListTimeout)
	defer cancel()
	accounts, err := unixidentity.LocalAccountRecords(ctx)
	if err != nil {
		return managedHookPeerListing{}, err
	}
	return localAccountsListing(accounts)
}

var errNoLocalAccounts = errors.New("the local account list is empty")

// accountRecordToken is the DirectoryFacts.AccountRecord of a listed local
// node record (managedHookPeerAccountRecord): "record:" and a digest of the
// record, "" for none.
func accountRecordToken(record string) string {
	if record == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(record))
	return "record:" + hex.EncodeToString(sum[:16])
}

// localAccountsListing digests the accounts without regard to order: a
// change of an account's name, uid, record, home or primary group changes
// the stamp and that account's record.
func localAccountsListing(accounts map[string]unixidentity.LocalAccountRecord) (managedHookPeerListing, error) {
	if len(accounts) == 0 {
		return managedHookPeerListing{}, errNoLocalAccounts
	}
	records := make(map[string]string, len(accounts))
	names := make([]string, 0, len(accounts))
	for name, account := range accounts {
		records[name] = fmt.Sprintf("%d\x00%s\x00%s\x00%s", account.UID, account.RecordID, account.Home, account.PrimaryGID)
		names = append(names, name)
	}
	sort.Strings(names)
	sum := sha256.New()
	for _, name := range names {
		fmt.Fprintf(sum, "%s\x00%s\n", name, records[name])
	}
	return managedHookPeerListing{stamp: "listed/" + hex.EncodeToString(sum.Sum(nil)[:16]), records: records}, nil
}
