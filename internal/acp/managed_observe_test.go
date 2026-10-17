// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// rel-1-0-3 GAP-0037: a standalone managed guard in observe mode refuses a
// frame it could not evaluate, as action mode does, instead of delivering
// it unchecked. An administrator who switched ACP checking off is an answer,
// and that frame still goes through. A per-user observe guard keeps
// delivering.
func TestManagedObserveGuardRefusesAFrameItCouldNotEvaluate(t *testing.T) {
	prompt := `{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}` + "\n"
	for _, tc := range []struct {
		name      string
		managed   bool
		err       error
		delivered bool
	}{
		{name: "managed, gateway did not answer", managed: true, err: errors.New("offline"), delivered: false},
		{name: "managed, gateway not ready", managed: true, err: fmt.Errorf("503: %w", ErrGatewayNotReady), delivered: false},
		{name: "managed, checking switched off", managed: true, err: ErrACPDisabled, delivered: true},
		{name: "per-user, gateway did not answer", managed: false, err: errors.New("offline"), delivered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var forwarded, client bytes.Buffer
			state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}, peerProtocolFixes: true}
			opts := ProxyOptions{Mode: ModeObserve, Evaluator: &recordingEvaluator{err: tc.err}, Managed: tc.managed, Stderr: io.Discard}
			if err := copyFrames(context.Background(), opts, state, ClientToAgent, strings.NewReader(prompt), &forwarded, &client); err != nil {
				t.Fatal(err)
			}
			if delivered := strings.Contains(forwarded.String(), `"id":7`); delivered != tc.delivered {
				t.Fatalf("delivered = %v, want %v: agent=%q client=%q", delivered, tc.delivered, forwarded.String(), client.String())
			}
			if !tc.delivered && !strings.Contains(client.String(), "not delivered") {
				t.Fatalf("the editor was not told why: %q", client.String())
			}
		})
	}
}
