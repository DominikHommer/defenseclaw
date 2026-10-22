// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The outage proof (1.0.4 guard: fail closed by class).
//
// The hook cannot learn of a revocation the gateway failed to write, so an
// allow must not outlive its proof. The protected allow records of a
// session are that proof: the hook accepts one during an outage for at most
// enterprisepolicy.PublishedSessionProofLifetime after the gateway last
// wrote it. So:
//
//   - every exchange that answers allow with the account's key keeps the
//     session's proof (keepForeignHookSessionProof), and this gateway renews
//     it every foreignHookSessionRenewEvery while it runs, as an exchange
//     would: under the account's locks, with the key and the guardian's
//     removals read again, from the private store's record of the session
//     (enterprisepolicy.ForeignHookSessionRenewable);
//   - a denial of the session stops its renewal at once
//     (dropForeignHookSessionProof); so do a revocation of the account that
//     is owed, a session the store no longer allows, and an agent that made
//     no exchange for foreignHookSessionProofIdle; a read that fails and a
//     closed account renew nothing until they are resolved;
//   - a gateway that does not answer the hooks renews nothing: before each
//     round it asks every listener the hooks call (the hook socket and the
//     TCP API it serves) for /health, and renews only when each answers
//     within foreignHookAnswerWithin and no exchange has been waiting longer
//     than that for its answer (foreignHookServing). A gateway that stops,
//     crashes, hangs, is wedged or has run out of connections therefore
//     renews nothing, whether or not its process still runs.
//
// Whatever write failed, an earlier allow therefore ends by itself at most
// the proof lifetime after its last renewal. A denial whose revocation
// writes fail also closes the account (foreignHookDenialRevocation), and
// reports the denial as FAILED, with the time the last allow ends, when
// that fails too.

// foreignHookSessionRenewEvery is how often the proofs are renewed, and
// foreignHookSessionProofIdle how long after its last exchange a session's
// proof is still renewed (replaceable in tests).
var (
	foreignHookSessionRenewEvery = enterprisepolicy.PublishedSessionRenewEvery
	foreignHookSessionProofIdle  = 15 * time.Minute
)

// foreignHookAnswerWithin is how long the gateway may take to answer a
// hook before it counts as not answering: the hook gives a session exchange
// at most 5 seconds (hookForeignGuardMaxScan in internal/cli), and then
// decides as in an outage (replaceable in tests).
var foreignHookAnswerWithin = 5 * time.Second

// foreignHookServing is what tells whether this gateway answers the hooks:
// the listeners the hooks call and the exchanges it is deciding now.
type foreignHookServing struct {
	mu        sync.Mutex
	listeners []net.Addr
	next      uint64
	deciding  map[uint64]time.Time
}

// serveForeignHooks records a listener the hooks call; the proofs are
// renewed only while each of them answers.
func (a *APIServer) serveForeignHooks(ln net.Listener) {
	s := &a.foreignHookServing
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, ln.Addr())
}

// decideForeignHookExchange marks an exchange being decided until the
// returned func is called.
func (a *APIServer) decideForeignHookExchange() func() {
	s := &a.foreignHookServing
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deciding == nil {
		s.deciding = map[uint64]time.Time{}
	}
	s.next++
	id := s.next
	s.deciding[id] = time.Now()
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.deciding, id)
	}
}

// foreignHookGatewayAnswering is nil only while this gateway answers the
// hooks: it serves at least one listener, no exchange has been waiting
// longer than foreignHookAnswerWithin, and every listener answers /health
// within it.
func (a *APIServer) foreignHookGatewayAnswering() error {
	s := &a.foreignHookServing
	s.mu.Lock()
	listeners := append([]net.Addr(nil), s.listeners...)
	var oldest time.Time
	for _, started := range s.deciding {
		if oldest.IsZero() || started.Before(oldest) {
			oldest = started
		}
	}
	s.mu.Unlock()
	if len(listeners) == 0 {
		return errors.New("no listener serves the hooks")
	}
	if !oldest.IsZero() && time.Since(oldest) > foreignHookAnswerWithin {
		return fmt.Errorf("an exchange has waited %s for its answer", time.Since(oldest).Round(time.Second))
	}
	for _, addr := range listeners {
		ctx, cancel := context.WithTimeout(context.Background(), foreignHookAnswerWithin)
		err := probeForeignHookListener(ctx, addr)
		cancel()
		if err != nil {
			return fmt.Errorf("the %s listener does not answer: %w", addr.Network(), err)
		}
	}
	return nil
}

// probeForeignHookListener asks the listener at addr for /health over a new
// connection, as a hook would connect; any HTTP answer is one.
func probeForeignHookListener(ctx context.Context, addr net.Addr) error {
	network, address := addr.Network(), addr.String()
	if tcp, ok := addr.(*net.TCPAddr); ok && (tcp.IP == nil || tcp.IP.IsUnspecified()) {
		address = net.JoinHostPort("127.0.0.1", fmt.Sprint(tcp.Port))
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/health", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// foreignHookSessionProof is one session whose proof this gateway renews:
// the account, the session key and when an exchange last allowed it.
type foreignHookSessionProof struct {
	identity string
	key      enterprisepolicy.SessionKey
	seen     time.Time
}

// foreignHookSessionProofs are the proofs this gateway process renews.
type foreignHookSessionProofs struct {
	mu     sync.Mutex
	proofs map[string]foreignHookSessionProof
}

func foreignHookSessionProofID(identity string, key enterprisepolicy.SessionKey) string {
	return strings.Join([]string{identity, key.Connector, key.Session, key.Process}, "\x00")
}

// keepForeignHookSessionProof renews the proof of key from now on (the
// caller answered it allow with the account's key).
func (a *APIServer) keepForeignHookSessionProof(identity string, key enterprisepolicy.SessionKey) {
	p := &a.foreignHookProofs
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proofs == nil {
		p.proofs = map[string]foreignHookSessionProof{}
	}
	p.proofs[foreignHookSessionProofID(identity, key)] = foreignHookSessionProof{identity: identity, key: key, seen: time.Now()}
}

// dropForeignHookSessionProof stops renewing every proof of identity's
// connector that shares the session or the agent process of key (the
// caller denied it).
func (a *APIServer) dropForeignHookSessionProof(identity string, key enterprisepolicy.SessionKey) {
	p := &a.foreignHookProofs
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, proof := range p.proofs {
		if proof.identity != identity || proof.key.Connector != key.Connector {
			continue
		}
		if (key.Session != "" && proof.key.Session == key.Session) || (key.Process != "" && proof.key.Process == key.Process) {
			delete(p.proofs, id)
		}
	}
}

// foreignHookSessionProofKept reports a proof still renewed, and forgets
// one whose agent made no exchange for foreignHookSessionProofIdle.
func (a *APIServer) foreignHookSessionProofKept(proof foreignHookSessionProof) bool {
	p := &a.foreignHookProofs
	p.mu.Lock()
	defer p.mu.Unlock()
	id := foreignHookSessionProofID(proof.identity, proof.key)
	current, ok := p.proofs[id]
	if ok && time.Since(current.seen) > foreignHookSessionProofIdle {
		delete(p.proofs, id)
		return false
	}
	return ok
}

// foreignHookSessionProofList is every proof renewed now.
func (a *APIServer) foreignHookSessionProofList() []foreignHookSessionProof {
	p := &a.foreignHookProofs
	p.mu.Lock()
	defer p.mu.Unlock()
	list := make([]foreignHookSessionProof, 0, len(p.proofs))
	for _, proof := range p.proofs {
		list = append(list, proof)
	}
	return list
}

// currentForeignHookSessionPlaces are the places of the gateway's data
// directory, and false where it publishes no records.
func (a *APIServer) currentForeignHookSessionPlaces() (foreignHookSessionPlaces, bool) {
	dataDir := strings.TrimSpace(a.configDataDir())
	if !filepath.IsAbs(dataDir) {
		return foreignHookSessionPlaces{}, false
	}
	places := a.foreignHookSessionPlaces(dataDir)
	return places, places.recordRoot != ""
}

// renewForeignHookSessionProofs renews every proof every interval until ctx
// ends.
func (a *APIServer) renewForeignHookSessionProofs(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.renewForeignHookSessionProofsOnce()
		}
	}
}

// renewForeignHookSessionProofsOnce renews every proof once.
func (a *APIServer) renewForeignHookSessionProofsOnce() {
	places, ok := a.currentForeignHookSessionPlaces()
	if !ok {
		return
	}
	proofs := a.foreignHookSessionProofList()
	if len(proofs) == 0 {
		return
	}
	if err := a.foreignHookGatewayAnswering(); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the gateway does not answer the hooks, so the outage proofs of %d sessions were not renewed and end within %s: %v\n",
			len(proofs), enterprisepolicy.PublishedSessionProofLifetime, err)
		return
	}
	for _, proof := range proofs {
		if err := a.renewForeignHookSessionProof(places, proof); err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the outage proof of a %s session was not renewed, so it ends within %s: %v\n",
				clipForeignHookAuditField(proof.key.Connector, 64), enterprisepolicy.PublishedSessionProofLifetime, err)
		}
	}
}

// errForeignHookProofNotRenewable is a proof the gateway stops renewing
// for good: the session is no longer allowed, or its account owes a
// revocation.
var errForeignHookProofNotRenewable = errors.New("the session's proof is no longer renewed")

// renewForeignHookSessionProof writes the allow records of one session
// again, as an exchange would answer it: under the account's exchange lock
// of this process and its removal lock, with the account's key read first,
// then the guardian's removals and the private store, while the account is
// not closed, and only within
// foreignHookExchangeHold of asking for the removal lock. Any doubt renews
// nothing. A proof a denial dropped meanwhile is not renewed.
func (a *APIServer) renewForeignHookSessionProof(places foreignHookSessionPlaces, proof foreignHookSessionProof) error {
	stateDir := enterprisepolicy.ForeignHookSessionStoreDir(places.dataDir, proof.identity)
	unlock := a.foreignHookSessionLocks.lock(stateDir)
	defer unlock()
	if !a.foreignHookSessionProofKept(proof) {
		return nil
	}
	answerBy := time.Now().Add(foreignHookExchangeHold)
	ctx, cancel := context.WithTimeout(context.Background(), foreignHookExchangeWait)
	release, err := foreignHookAccountExchangeLock(ctx, places.dataDir, proof.identity)
	cancel()
	if err != nil {
		return fmt.Errorf("the account's removal lock: %w", err)
	}
	defer release()
	if a.foreignHookRevocationOwed(places, proof.identity) {
		a.dropForeignHookSessionProof(proof.identity, proof.key)
		return fmt.Errorf("%w: a revocation of the account is owed", errForeignHookProofNotRenewable)
	}
	if err := enterprisepolicy.PublishedSessionAccountClosed(places.recordRoot, proof.identity); err != nil {
		// Renewed again once the account is open (a revocation took).
		return err
	}
	recordKey, err := foreignHookSessionKey(places.recordRoot, proof.identity)
	if err != nil {
		return fmt.Errorf("the account's record key: %w", err)
	}
	removals, ledgerErr := a.foreignHookRemovals.forIdentity(places.removalsDir, proof.identity)
	if err := enterprisepolicy.ForeignHookSessionRenewable(stateDir, proof.key, removals, ledgerErr, time.Now()); err != nil {
		a.dropForeignHookSessionProof(proof.identity, proof.key)
		return fmt.Errorf("%w: %v", errForeignHookProofNotRenewable, err)
	}
	if !time.Now().Before(answerBy) {
		return errForeignHookExchangeExpired
	}
	return foreignHookSessionPublish(places.recordRoot, proof.identity, proof.key, enterprisepolicy.GuardDecision{}, recordKey, time.Now())
}
