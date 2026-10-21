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

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func recordedChanges(t *testing.T, env *Env) []enterprisestatus.ChangeEvent {
	t.Helper()
	dir := env.P(enterprisestatus.ChangeEventsDir(env.Layout.ConfigDir))
	var out []enterprisestatus.ChangeEvent
	for _, id := range enterprisestatus.ListChangeEventIDs(dir) {
		path := filepath.Join(dir, id+".json")
		ev, err := enterprisestatus.ReadChangeEvent(path)
		if err != nil {
			t.Fatal(err)
		}
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
			t.Fatalf("change event %s mode: %v, %v", id, info, err)
		}
		out = append(out, ev)
	}
	if len(out) > 0 {
		if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o750 {
			t.Fatalf("change spool mode: %v, %v", info, err)
		}
	}
	return out
}

// Every anchor install that changed the file, was refused or failed leaves
// one change event for the gateway; a byte-identical install leaves none.
func TestInstallBundleAnchorsRecordsEachChange(t *testing.T) {
	b, dest := newAnchorsHost(t)
	before := readFile(t, dest)
	previous, err := enterprisebundle.DecodeAnchors([]byte(before))
	if err != nil {
		t.Fatal(err)
	}
	var previousIDs []string
	for _, key := range previous.Keys {
		previousIDs = append(previousIDs, key.KeyID)
	}
	doc := anchorsDoc(t, b, "k1:active", "k9:active")
	src, base := agentAnchors(t, doc)
	b.env.Trust = modeTrust(base, b.env.Root)
	if _, err := b.env.InstallBundleAnchors(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	changes := recordedChanges(t, b.env)
	added, removed := enterprisestatus.ChangedKeyIDs(previousIDs, []string{"k1", "k9"})
	if len(changes) != 1 || changes[0].Outcome != enterprisestatus.ChangeApplied || changes[0].Kind != enterprisestatus.ChangeKindTrustAnchors ||
		changes[0].SHA256 != sha256Bytes([]byte(doc)) || changes[0].PreviousSHA256 != sha256Bytes([]byte(before)) ||
		!reflect.DeepEqual(changes[0].KeyIDsAdded, added) || !reflect.DeepEqual(changes[0].KeyIDsRemoved, removed) ||
		len(added) == 0 {
		t.Fatalf("changes = %+v (want added %v removed %v)", changes, added, removed)
	}

	// The same bytes again write nothing and record nothing.
	if out, err := b.env.InstallBundleAnchors(context.Background(), src); err != nil || out.Result != AnchorsUnchanged {
		t.Fatalf("same bytes = %+v, %v", out, err)
	}
	if got := recordedChanges(t, b.env); len(got) != 1 {
		t.Fatalf("an unchanged install recorded %d events", len(got)-1)
	}

	// A file that is not an anchor file is refused before anything is written.
	bad, badBase := agentAnchors(t, "{")
	b.env.Trust = modeTrust(badBase, b.env.Root)
	if _, err := b.env.InstallBundleAnchors(context.Background(), bad); enterprisebundle.CodeOf(err) != enterprisebundle.CodeAnchorInvalid {
		t.Fatalf("bad file: %v", err)
	}
	// A write whose installed file fails its check is put back: a failure.
	next := anchorsDoc(t, b, "k1:active")
	nextSrc, nextBase := agentAnchors(t, next)
	check := modeTrust(nextBase, b.env.Root)
	b.env.Trust = func(path string, kind TrustKind) error {
		if raw, err := os.ReadFile(path); err == nil && path == dest && string(raw) == next {
			return fmt.Errorf("%s: owner uid 1000 is not trusted", path)
		}
		return check(path, kind)
	}
	if _, err := b.env.InstallBundleAnchors(context.Background(), nextSrc); enterprisebundle.CodeOf(err) != enterprisebundle.CodeAnchorInsecure {
		t.Fatalf("failed post-check: %v", err)
	}
	changes = recordedChanges(t, b.env)
	if len(changes) != 3 ||
		changes[1].Outcome != enterprisestatus.ChangeRefused || changes[1].ReasonCode != "anchor_invalid" ||
		changes[1].SHA256 != sha256Bytes([]byte(doc)) || len(changes[1].KeyIDsAdded) != 0 ||
		changes[2].Outcome != enterprisestatus.ChangeFailed || changes[2].ReasonCode != "anchor_insecure" {
		t.Fatalf("changes = %+v", changes)
	}
}

// A caller that is not root records nothing (it cannot write the spool).
func TestInstallBundleAnchorsRecordsNothingWithoutRoot(t *testing.T) {
	b, _ := newAnchorsHost(t)
	src, base := agentAnchors(t, anchorsDoc(t, b, "k1:active"))
	b.env.Trust = modeTrust(base, b.env.Root)
	b.env.Geteuid = func() int { return 1000 }
	if _, err := b.env.InstallBundleAnchors(context.Background(), src); err == nil {
		t.Fatal("a standard account installed trust anchors")
	}
	if got := recordedChanges(t, b.env); len(got) != 0 {
		t.Fatalf("recorded %+v", got)
	}
}

type failingLookupAccounts struct{ AccountManager }

func (failingLookupAccounts) Lookup(context.Context, string) (Account, bool, error) {
	return Account{}, false, errors.New("getent: the name service did not answer")
}

// A service account lookup that fails never gives the change spool root's
// group, which would lock the gateway out of it. The install is refused
// before the anchor file is written (a change that cannot be recorded is not
// made), the spool keeps the service group, and the result says the refusal
// itself could not be recorded.
func TestInstallBundleAnchorsRefusedWhenTheChangeCannotBeRecorded(t *testing.T) {
	b, dest := newAnchorsHost(t)
	b.accounts.accounts[b.env.Layout.ServiceUser] = Account{Name: b.env.Layout.ServiceUser, UID: 991, GID: 988}
	spool := b.env.P(enterprisestatus.ChangeEventsDir(b.env.Layout.ConfigDir))
	if err := b.env.ChangeSpoolReady(); err != nil {
		t.Fatal(err)
	}
	if got := b.owners[spool]; got != [2]int{0, 988} {
		t.Fatalf("spool owner = %v, want root with the service group", got)
	}
	before := readFile(t, dest)
	b.env.Accounts = failingLookupAccounts{b.env.Accounts}
	src, base := agentAnchors(t, anchorsDoc(t, b, "k1:active", "k9:active"))
	b.env.Trust = modeTrust(base, b.env.Root)
	out, err := b.env.InstallBundleAnchors(context.Background(), src)
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeStateInvalid || !strings.Contains(err.Error(), "cannot record the trust anchor change") {
		t.Fatalf("install with an unknown spool owner: %v", err)
	}
	if readFile(t, dest) != before {
		t.Fatal("the anchor file was written though its change could not be recorded")
	}
	if got := b.owners[spool]; got != [2]int{0, 988} {
		t.Fatalf("spool owner = %v after a failed lookup, want root with the service group", got)
	}
	if out == nil || out.Unrecorded == nil {
		t.Fatalf("result %+v does not say the refusal was not recorded", out)
	}
	if got := recordedChanges(t, b.env); len(got) != 0 {
		t.Fatalf("recorded %+v", got)
	}
}

// Before the service account exists, an existing spool keeps its group.
func TestChangeSpoolKeepsItsGroupBeforeTheServiceAccountExists(t *testing.T) {
	b, _ := newAnchorsHost(t)
	delete(b.accounts.accounts, b.env.Layout.ServiceUser)
	spool := b.env.P(enterprisestatus.ChangeEventsDir(b.env.Layout.ConfigDir))
	if err := os.MkdirAll(spool, 0o750); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(spool)
	if err != nil {
		t.Fatal(err)
	}
	gid := int(info.Sys().(*syscall.Stat_t).Gid)
	if err := b.env.ChangeSpoolReady(); err != nil {
		t.Fatal(err)
	}
	if got := b.owners[spool]; got != [2]int{0, gid} {
		t.Fatalf("spool owner = %v, want root with the folder's group %d", got, gid)
	}
}
