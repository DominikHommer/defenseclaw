// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// Review P1 (1.0.4 guard loop round 3): the hook cannot see a revocation
// the operating system refused when the folders still look writable. So an
// allow passes an outage only once the gateway that wrote it ended cleanly:
// while its run mark is there (it still runs, it stopped owing a
// revocation, or it crashed) every allow blocks, whatever its MAC. A mark
// that is not a plain file blocks too. A block still denies with its
// reason.
func TestPublishedSessionOutageNeedsTheGatewayToHaveEndedCleanly(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if err := publishCurrent(root, identity, key, GuardDecision{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a fresh allow of a gateway that ended cleanly proves the session")
	}

	found, err := MarkPublishedSessionGatewayRunning(root)
	if err != nil || found {
		t.Fatalf("the first run adds its mark: found %v, %v", found, err)
	}
	got, err := CheckPublishedForeignHookSession(root, identity, key, GuardDecision{}, trustAll)
	if !errors.Is(err, ErrPublishedSessionUnavailable) || got.Deny {
		t.Fatalf("an allow while the gateway's run mark is there: %+v, %v; want ErrPublishedSessionUnavailable", got, err)
	}
	// A run that finds the mark is told: the earlier run did not end cleanly.
	if found, err := MarkPublishedSessionGatewayRunning(root); err != nil || !found {
		t.Fatalf("a run after one that did not end cleanly finds the mark: found %v, %v", found, err)
	}

	blocked := SessionKey{Connector: "copilot", Session: "s-2", Process: "p-2"}
	if err := publishCurrent(root, identity, blocked, GuardDecision{Deny: true, Reason: foreignHookBlockedPrefix + " test block"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckPublishedForeignHookSession(root, identity, blocked, GuardDecision{}, trustAll); err != nil || !got.Deny {
		t.Fatalf("a block still denies with its reason while the mark is there: %+v, %v", got, err)
	}

	if err := EndPublishedSessionGatewayRun(root); err != nil {
		t.Fatal(err)
	}
	if !publishedSessionTestAllows(root, identity, key) {
		t.Fatal("once the gateway ended cleanly its fresh allow proves the session again")
	}
	if err := EndPublishedSessionGatewayRun(root); err != nil {
		t.Fatalf("ending a run mark that is not there: %v", err)
	}

	// A mark that is not a plain file is a mark, and the run that finds it
	// has none of its own.
	path, _ := publishedSessionGatewayRunPath(root)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if found, err := MarkPublishedSessionGatewayRunning(root); err == nil || !found {
		t.Fatalf("a run mark that is a folder: found %v, %v; want found and an error", found, err)
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("a run mark that is a folder lets the allow prove the session")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// A mark that cannot be added is an error: that run publishes no key.
	previous := publishedSessionCreateMarkFile
	t.Cleanup(func() { publishedSessionCreateMarkFile = previous })
	publishedSessionCreateMarkFile = func(string) error { return fmt.Errorf("the folder takes no change") }
	if found, err := MarkPublishedSessionGatewayRunning(root); err == nil || found {
		t.Fatalf("a run mark the folder refuses: found %v, %v; want an error", found, err)
	}
}

// RevokeAllPublishedSessionKeys ends every account's key, the way a block
// ends one, and says when one may still be alive.
func TestRevokeAllPublishedSessionKeysEndsEveryAccount(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	other := publishedSessionOtherIdentity(identity)
	key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	for _, account := range []string{identity, other} {
		if err := publishCurrent(root, account, key, GuardDecision{}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := RevokeAllPublishedSessionKeys(root); err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{identity, other} {
		if _, err := ReadPublishedSessionKey(root, account); err == nil {
			t.Fatalf("%s keeps a key", account)
		}
	}
	if publishedSessionTestAllows(root, identity, key) {
		t.Fatal("an allow from before the revocation of every key proves the session")
	}

	// A key that can be neither removed nor marked revoked is alive.
	if err := RotatePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
		t.Fatal(err)
	}
	previousRemove, previousMark := publishedSessionRemoveKey, publishedSessionCreateMarkFile
	t.Cleanup(func() { publishedSessionRemoveKey, publishedSessionCreateMarkFile = previousRemove, previousMark })
	publishedSessionRemoveKey = func(string) error { return fmt.Errorf("refused") }
	publishedSessionCreateMarkFile = func(string) error { return fmt.Errorf("refused") }
	if err := RevokeAllPublishedSessionKeys(root); !errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("a key that took no change: %v, want ErrPublishedSessionKeyAlive", err)
	}
	publishedSessionRemoveKey, publishedSessionCreateMarkFile = previousRemove, previousMark

	// A record folder that cannot be listed is not known to hold no key.
	previousList := publishedSessionList
	t.Cleanup(func() { publishedSessionList = previousList })
	publishedSessionList = func(string) ([]string, error) { return nil, fmt.Errorf("listing refused") }
	if err := RevokeAllPublishedSessionKeys(root); !errors.Is(err, ErrPublishedSessionKeyAlive) {
		t.Fatalf("a record folder that cannot be listed: %v, want ErrPublishedSessionKeyAlive", err)
	}
}
