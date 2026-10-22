// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The gateway's run mark (any doubt blocks).
//
// The hook cannot see a revocation the operating system refused when the
// refusal leaves the folders looking writable, so during an outage it
// trusts the protected records only after the gateway that wrote them ended
// cleanly (enterprisepolicy.MarkPublishedSessionGatewayRunning):
//
//   - before it answers anything, a standalone gateway adds its run mark to
//     the folder of the revocation marks; a gateway without the mark (it
//     could not be added) publishes no allow with a key, and first ends
//     every account's key, so no allow of an earlier run passes an outage
//     either;
//   - a gateway that finds the mark (its previous run did not end cleanly:
//     a crash, a kill, a host that lost power, or a stop that owed a
//     revocation) owes the revocation of every account's key
//     (oweAllForeignHookRevocations): until it takes, no allow carries a
//     key;
//   - as its very last step, once its servers stopped and the owed
//     revocations were tried once more, it removes the mark, but only when
//     nothing is owed, saved or not. A revocation owed after that (a late
//     exchange) adds the mark again.
//
// So an allow passes an outage only after a stop with nothing owed; a
// gateway that still runs and does not answer, or that ended any other way,
// leaves every guarded call blocked until it is back.

// foreignHookSessionMarkRun adds the gateway's run mark,
// foreignHookSessionEndRun removes it, and foreignHookSessionKillAll ends
// every account's key (enterprisepolicy; replaceable in tests).
var (
	foreignHookSessionMarkRun = enterprisepolicy.MarkPublishedSessionGatewayRunning
	foreignHookSessionEndRun  = enterprisepolicy.EndPublishedSessionGatewayRun
	foreignHookSessionKillAll = enterprisepolicy.RevokeAllPublishedSessionKeys
)

// foreignHookGatewayRun is this gateway's run mark: the record folder it is
// for, whether this run began and ended, and whether it holds the mark.
type foreignHookGatewayRun struct {
	mu     sync.Mutex
	root   string
	begun  bool
	ended  bool
	marked bool
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

// beginForeignHookGatewayRun adds the run mark before the gateway answers
// anything (a no-op where it publishes no records).
func (a *APIServer) beginForeignHookGatewayRun() {
	places, ok := a.currentForeignHookSessionPlaces()
	if !ok {
		return
	}
	run := &a.foreignHookRun
	run.mu.Lock()
	defer run.mu.Unlock()
	run.root, run.begun, run.ended, run.marked = places.recordRoot, true, false, false
	a.markForeignHookGatewayRunLocked(places)
}

// keepForeignHookGatewayRun adds the run mark again while this run has
// none (the API server's retry loop runs it every second).
func (a *APIServer) keepForeignHookGatewayRun() {
	run := &a.foreignHookRun
	run.mu.Lock()
	defer run.mu.Unlock()
	if !run.begun || run.marked || run.ended {
		return
	}
	if places, ok := a.currentForeignHookSessionPlaces(); ok && places.recordRoot == run.root {
		a.markForeignHookGatewayRunLocked(places)
	}
}

// markForeignHookGatewayRunLocked adds the run mark (the caller holds
// run.mu). A mark an earlier run left, and a mark that could not be added,
// owe the revocation of every account's key.
func (a *APIServer) markForeignHookGatewayRunLocked(places foreignHookSessionPlaces) {
	run := &a.foreignHookRun
	found, err := foreignHookSessionMarkRun(places.recordRoot)
	if found || err != nil {
		a.oweAllForeignHookRevocations(places)
	}
	if found {
		fmt.Fprintln(os.Stderr, "[gateway] foreign-hook session: an earlier gateway run did not end cleanly; every account's protected session record key is ended before an allow carries one again, and guarded calls block during an outage until the gateway stops cleanly")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the gateway run mark could not be added, so no allow carries a key and guarded calls block during an outage; it is tried again every second: %v\n", err)
		return
	}
	run.marked = true
}

// foreignHookGatewayRunUnmarked reports a run that began without its mark:
// none of its allows may carry a key.
func (a *APIServer) foreignHookGatewayRunUnmarked() bool {
	run := &a.foreignHookRun
	run.mu.Lock()
	defer run.mu.Unlock()
	return run.begun && !run.marked && !run.ended
}

// endForeignHookGatewayRun is the gateway's last step: it removes the run
// mark when nothing is owed, saved or not. Otherwise the mark stays, and
// the hook blocks every guarded call during the outage.
func (a *APIServer) endForeignHookGatewayRun() {
	run := &a.foreignHookRun
	run.mu.Lock()
	defer run.mu.Unlock()
	if !run.begun || run.ended {
		return
	}
	run.ended = true
	if !run.marked {
		return
	}
	places, ok := a.currentForeignHookSessionPlaces()
	if !ok || places.recordRoot != run.root || a.foreignHookRevocationsOwedAny(places.dataDir) {
		fmt.Fprintln(os.Stderr, "[gateway] foreign-hook session: a revocation of protected session records is still owed, so the gateway run mark stays and guarded calls block during the outage")
		return
	}
	if err := foreignHookSessionEndRun(run.root); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the gateway run mark could not be removed, so guarded calls block during the outage: %v\n", err)
		return
	}
	run.marked = false
}

// remarkForeignHookGatewayRunAfterEnd adds the run mark again when a
// revocation is owed after the run ended (an exchange that finished after
// the last step).
func (a *APIServer) remarkForeignHookGatewayRunAfterEnd() {
	run := &a.foreignHookRun
	run.mu.Lock()
	defer run.mu.Unlock()
	if !run.begun || !run.ended || run.marked {
		return
	}
	if _, err := foreignHookSessionMarkRun(run.root); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the gateway run mark could not be added again for a revocation owed as the gateway stopped: %v\n", err)
		return
	}
	run.marked = true
}
