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

package egress

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

// GAP-0172: Options.Refresh runs before a new tunnel or forwarded request is
// decided. A policy it changed decides the request (the credential's new
// decider), a refusal it returns answers like a suspended credential's, and
// an unchanged policy keeps the decider the request authenticated with. A
// request without a known credential never reaches it.
func TestProxyRefreshDecidesWithTheCurrentPolicy(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var next func() (bool, *Decision)
	h := newHarness(t, func(c *harnessConfig) {
		c.opts.Refresh = func(pr Principal) (bool, *Decision) {
			mu.Lock()
			seen = append(seen, pr.BindingID)
			fn := next
			mu.Unlock()
			if fn == nil {
				return false, nil
			}
			return fn()
		}
	})
	set := func(fn func() (bool, *Decision)) {
		mu.Lock()
		next = fn
		mu.Unlock()
	}
	h.dialer.route(443, startEcho(t))
	h.serve(80, answerOK)

	if conn, br := h.openTunnel(h.cred, "example.com:443", ""); !relays(conn, br) {
		t.Fatal("no tunnel under the unchanged policy")
	}

	// Tightened while the sandbox runs: the refresh registers the credential
	// again with a decider that blocks example.com.
	set(func() (bool, *Decision) {
		pr := h.pr
		pr.Decider = h.newDecider(DeciderOptions{Unblocks: h.unblocks, Block: []string{"example.com"}})
		must(t, h.creds.Register(h.cred, pr))
		return true, nil
	})
	if resp, body := h.refused(h.cred, "example.com:443"); resp.status != http.StatusForbidden || body.Host != "example.com" ||
		body.Category == CategoryEgressOff {
		t.Fatalf("tightened CONNECT = %d %+v", resp.status, body)
	}
	if res, data := fetch(t, h.clientFor(h.cred, nil), "http://example.com/"); res.StatusCode != http.StatusForbidden {
		t.Fatalf("tightened forwarded GET = %d %s", res.StatusCode, data)
	}

	// Changed and not confirmed: refused as a suspended credential is.
	set(func() (bool, *Decision) { off := testEgressOff; return false, &off })
	if resp, body := h.refused(h.cred, "example.com:443"); resp.status != http.StatusForbidden || body.Category != CategoryEgressOff ||
		body.Host != "example.com" || body.Port != 443 {
		t.Fatalf("unconfirmed CONNECT = %d %+v", resp.status, body)
	}
	if res, data := fetch(t, h.clientFor(h.cred, nil), "http://example.com/"); res.StatusCode != http.StatusForbidden ||
		!strings.Contains(string(data), "egress_off") {
		t.Fatalf("unconfirmed forwarded GET = %d %s", res.StatusCode, data)
	}

	// Loosened again.
	set(func() (bool, *Decision) {
		must(t, h.creds.Register(h.cred, h.pr))
		return true, nil
	})
	if conn, br := h.openTunnel(h.cred, "example.com:443", ""); !relays(conn, br) {
		t.Fatal("no tunnel after the policy was loosened")
	}

	mu.Lock()
	before := len(seen)
	mu.Unlock()
	conn, _, resp := h.connect("example.com:443", "", nil)
	_ = conn.Close()
	mu.Lock()
	defer mu.Unlock()
	if resp.status != http.StatusProxyAuthRequired || len(seen) != before {
		t.Fatalf("unauthenticated CONNECT = %d, refreshes %d -> %d", resp.status, before, len(seen))
	}
	for _, id := range seen {
		if id != h.pr.BindingID {
			t.Fatalf("refreshed principals %v", seen)
		}
	}
}
