// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// Review P1 (1.0.4 guard loop round 3): alice has a fresh allow. A block of
// alice then fails every revocation write in a way the hook cannot see: the
// key's removal and its mark are refused, the block record is not written,
// and the owed revocation cannot even be saved. The gateway stops (or
// crashes and loses what it owed in memory). No allow may pass that outage:
// the gateway's run mark stays, and the hook trusts no record while it is
// there, for any account. A restarted gateway that finds the mark ends
// every account's key before an allow carries one again, and a run that
// then ends with nothing owed lets fresh allows pass the next outage.
func TestForeignHookSessionOutageAfterAnUnsettledRevocationBlocks(t *testing.T) {
	server := newForeignHookRealPublishTestServer(t)
	process := runtime.GOOS + ":b:1:500"
	key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
	outage := func(identity string) error {
		t.Helper()
		got, err := foreignHookOutageCheck(server, identity, key)
		if err == nil && got.Deny {
			return errors.New("denied")
		}
		return err
	}
	allowBoth := func() {
		t.Helper()
		for _, identity := range []struct{ id, token string }{{server.alice, server.aliceToken}, {server.bob, server.bobToken}} {
			if got := server.call(identity.token, foreignHookTestCall("s-1", process, true)); got.Deny {
				t.Fatalf("%s's clean session start: %+v", identity.id, got)
			}
		}
	}

	server.api.beginForeignHookGatewayRun()
	allowBoth()
	if err := outage(server.alice); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("while the gateway runs (and does not answer) nothing passes: %v", err)
	}
	server.api.endForeignHookGatewayRun()
	for _, identity := range []string{server.alice, server.bob} {
		if err := outage(identity); err != nil {
			t.Fatalf("after a clean stop %s's fresh allow passes the outage: %v", identity, err)
		}
	}

	// The next run. Every revocation write of alice's block fails.
	server.api.foreignHookRun = foreignHookGatewayRun{}
	server.api.beginForeignHookGatewayRun()
	allowBoth()
	aliceKey := server.keyID(server.alice)
	var refuse atomic.Bool
	var tries atomic.Int32
	refusedForeignHookSessionKill(t, &refuse, &tries)
	refuse.Store(true)
	previousKillAll := foreignHookSessionKillAll
	foreignHookSessionKillAll = func(root string) error {
		if refuse.Load() {
			return errors.Join(enterprisepolicy.ErrPublishedSessionKeyAlive, errors.New("the key folder takes no change"))
		}
		return previousKillAll(root)
	}
	t.Cleanup(func() { foreignHookSessionKillAll = previousKillAll })
	previousPublish := foreignHookSessionPublish
	foreignHookSessionPublish = func(root, identity string, k enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, now time.Time) error {
		if decision.Deny {
			return errors.New("the account folder takes no change")
		}
		return previousPublish(root, identity, k, decision, recordKey, now)
	}
	t.Cleanup(func() { foreignHookSessionPublish = previousPublish })
	owedDir := filepath.Join(server.dataDir, foreignHookRevocationsOwedDirName)
	if err := os.WriteFile(owedDir, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-1", process)); !got.Deny {
		t.Fatalf("the session start that found the hook is blocked: %+v", got)
	}
	if server.keyID(server.alice) != aliceKey {
		t.Fatal("the refused revocation must leave alice's key")
	}
	server.api.endForeignHookGatewayRun()
	if err := outage(server.alice); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("alice's earlier allow after a block no folder took, with the gateway stopped: %v, want ErrPublishedSessionUnavailable", err)
	}
	if err := outage(server.bob); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("no allow passes an outage that began owing a revocation: %v", err)
	}

	// A crash and a restart: what was owed in memory is gone, the mark is not.
	foreignHookSessionPublish = previousPublish
	refuse.Store(false)
	if err := os.Remove(owedDir); err != nil {
		t.Fatal(err)
	}
	server.api.foreignHookOwed = foreignHookRevocationsOwed{}
	server.api.foreignHookRun = foreignHookGatewayRun{}
	server.api.beginForeignHookGatewayRun()
	if got := server.call(server.bobToken, foreignHookTestCall("s-1", process, false)); got.Deny {
		t.Fatalf("bob is answered online: %+v", got)
	}
	if server.keyID(server.alice) != "" || server.keyID(server.bob) != "" {
		t.Fatal("a gateway whose previous run did not end cleanly ends every account's key first")
	}
	server.api.endForeignHookGatewayRun()
	for _, identity := range []string{server.alice, server.bob} {
		if err := outage(identity); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
			t.Fatalf("%s's allow from before the restart: %v, want ErrPublishedSessionUnavailable", identity, err)
		}
	}

	// The guardian makes new keys; a run that ends owing nothing lets its
	// fresh allows pass the next outage again.
	server.newKey(server.alice)
	server.newKey(server.bob)
	server.api.foreignHookRun = foreignHookGatewayRun{}
	server.api.beginForeignHookGatewayRun()
	// Alice's blocked session stays blocked; a new agent of hers is clean.
	process, key = runtime.GOOS+":b:2:700", enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-3", Process: runtime.GOOS + ":b:2:700"}
	for _, identity := range []struct{ id, token string }{{server.alice, server.aliceToken}, {server.bob, server.bobToken}} {
		if got := server.call(identity.token, foreignHookTestCall("s-3", process, true)); got.Deny {
			t.Fatalf("%s's new clean session start: %+v", identity.id, got)
		}
	}
	server.api.endForeignHookGatewayRun()
	for _, identity := range []string{server.alice, server.bob} {
		if err := outage(identity); err != nil {
			t.Fatalf("%s's fresh allow after a clean stop: %v", identity, err)
		}
	}

	// A revocation owed after the last step (an exchange that finished
	// late) puts the mark back.
	server.api.oweForeignHookRevocation(server.api.foreignHookSessionPlaces(server.dataDir), server.alice)
	if err := outage(server.bob); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("a revocation owed after the run ended: %v, want ErrPublishedSessionUnavailable", err)
	}
}

// A run that could not add its run mark publishes no allow with a key,
// and first ends every account's key: no allow of an earlier run passes an
// outage the hook could not be told about. Once the mark is added (the
// retry loop tries every second), allows carry the account's key again.
func TestForeignHookSessionRunWithoutItsMarkPublishesNoKey(t *testing.T) {
	server := newForeignHookRealPublishTestServer(t)
	process := runtime.GOOS + ":b:1:500"
	key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: process}
	if got := server.call(server.bobToken, foreignHookTestCall("s-1", process, true)); got.Deny {
		t.Fatalf("bob's clean session start: %+v", got)
	}
	var refuse atomic.Bool
	refuse.Store(true)
	previousMark := foreignHookSessionMarkRun
	foreignHookSessionMarkRun = func(root string) (bool, error) {
		if refuse.Load() {
			return false, errors.New("the mark folder takes no change")
		}
		return previousMark(root)
	}
	t.Cleanup(func() { foreignHookSessionMarkRun = previousMark })
	server.api.beginForeignHookGatewayRun()
	if got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, true)); got.Deny {
		t.Fatalf("alice's clean session start: %+v", got)
	}
	if server.keyID(server.alice) != "" || server.keyID(server.bob) != "" {
		t.Fatal("a run without its mark ends every account's key first")
	}
	if _, err := foreignHookOutageCheck(server, server.bob, key); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("bob's allow of an earlier run: %v, want ErrPublishedSessionUnavailable", err)
	}
	server.newKey(server.alice)
	if got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, false)); got.Deny {
		t.Fatalf("alice's clean call: %+v", got)
	}
	if _, err := foreignHookOutageCheck(server, server.alice, key); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
		t.Fatalf("an allow of a run without its mark carries no key: %v, want ErrPublishedSessionUnavailable", err)
	}

	refuse.Store(false)
	server.api.payOwedForeignHookRevocations()
	if got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, false)); got.Deny {
		t.Fatalf("alice's clean call: %+v", got)
	}
	server.api.endForeignHookGatewayRun()
	if got, err := foreignHookOutageCheck(server, server.alice, key); err != nil || got.Deny {
		t.Fatalf("once the run has its mark, its allows carry the key and pass after a clean stop: %+v %v", got, err)
	}
}
