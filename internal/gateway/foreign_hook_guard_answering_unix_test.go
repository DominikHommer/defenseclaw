// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The 1.0.4 guard review (proof renewal while the gateway answers): a
// gateway whose process runs but that does not answer the hooks renews no
// proof, so the hooks decide in outage mode and no earlier allow passes
// past its lifetime. Before, the renewal ran on its own ticker for 15
// minutes after the session's last exchange, whatever the hooks got. Each
// way the gateway can fail to answer: a listener that takes connections
// but never answers (wedged, out of handler capacity), a listener that
// takes none, and an exchange that waits on the gateway past the hook's
// budget. Once the gateway answers again, the proof is renewed again.
func TestForeignHookSessionProofIsRenewedOnlyWhileTheGatewayAnswers(t *testing.T) {
	for _, tc := range []struct {
		name string
		// stall makes the gateway not answer and returns what ends it.
		stall func(t *testing.T, server *foreignHookPublishTestServer) (resume func())
	}{
		{name: "a listener takes connections but never answers", stall: func(t *testing.T, server *foreignHookPublishTestServer) func() {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			server.api.serveForeignHooks(ln)
			return func() { foreignHookServeForTest(ln) }
		}},
		{name: "a listener takes no connection", stall: func(t *testing.T, server *foreignHookPublishTestServer) func() {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server.api.serveForeignHooks(ln)
			_ = ln.Close()
			return func() { foreignHookForgetListenersForTest(server, ln.Addr()) }
		}},
		{name: "an exchange waits on the gateway past the hook's budget", stall: func(t *testing.T, server *foreignHookPublishTestServer) func() {
			blocked, release := make(chan struct{}), make(chan struct{})
			previous := foreignHookSessionKey
			foreignHookSessionKey = func(root, identity string) (enterprisepolicy.SessionRecordKey, error) {
				if identity == server.bob {
					close(blocked)
					<-release
				}
				return previous(root, identity)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.exchange(server.bobToken, foreignHookTestCall("s-9", runtime.GOOS+":b:2:500", false))
			}()
			<-blocked
			foreignHookSessionKey = previous
			time.Sleep(2 * foreignHookAnswerWithin)
			return func() {
				close(release)
				<-done
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newForeignHookRealPublishTestServer(t)
			previousWithin := foreignHookAnswerWithin
			foreignHookAnswerWithin = 200 * time.Millisecond
			t.Cleanup(func() { foreignHookAnswerWithin = previousWithin })
			writes := countForeignHookAllowWrites(t)
			key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: runtime.GOOS + ":b:1:500"}
			if got := server.call(server.aliceToken, foreignHookTestCall("s-1", key.Process, true)); got.Deny {
				t.Fatalf("alice's clean session start: %+v", got)
			}
			before := writes.of(server.alice)
			server.api.renewForeignHookSessionProofsOnce()
			if writes.of(server.alice) != before+1 {
				t.Fatalf("a gateway that answers renews the proof: %d writes, want %d", writes.of(server.alice), before+1)
			}

			resume := tc.stall(t, server)
			stalled := writes.of(server.alice)
			for range 3 {
				server.api.renewForeignHookSessionProofsOnce()
			}
			if writes.of(server.alice) != stalled {
				t.Fatalf("a gateway that does not answer renewed the proof: %d writes, want %d", writes.of(server.alice), stalled)
			}
			if err := foreignHookOutageAfter(server, server.alice, key, foreignHookProofExpired); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
				t.Fatalf("the earlier allow 90 s after its last renewal: %v, want ErrPublishedSessionUnavailable", err)
			}

			resume()
			server.api.renewForeignHookSessionProofsOnce()
			if writes.of(server.alice) != stalled+1 {
				t.Fatalf("the gateway answers again and renews the proof: %d writes, want %d", writes.of(server.alice), stalled+1)
			}
			if err := foreignHookOutageAfter(server, server.alice, key, 0); err != nil {
				t.Fatalf("the renewed allow: %v", err)
			}
		})
	}
}

// foreignHookServeForTest answers on ln as the hook listener does.
func foreignHookServeForTest(ln net.Listener) {
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
			_ = conn.Close()
		}
	}()
}

// foreignHookForgetListenersForTest stops probing addr (a listener that
// was closed for good).
func foreignHookForgetListenersForTest(server *foreignHookPublishTestServer, addr net.Addr) {
	s := &server.api.foreignHookServing
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.listeners[:0]
	for _, listener := range s.listeners {
		if listener.String() != addr.String() {
			kept = append(kept, listener)
		}
	}
	s.listeners = kept
}
