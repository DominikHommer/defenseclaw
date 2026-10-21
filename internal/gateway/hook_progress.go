// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A hook of a tool call waits at most hookexec's answer budget (about four
// seconds) for the gateway's decision and then fails closed, so a restart, a
// repair or a busy host never holds the agent's tool call longer than that.
// A decision that waits on a remote scanner (Cisco AI Defense, the LLM
// judge) can take longer for a good reason: the gateway then reports it with
// one informational 102 response, and the hook keeps its whole budget. Only
// requests that carry hookexec.HookProgressHeader get the report; other
// clients never see an informational response.

type hookProgressContextKey struct{}

// hookProgressWriter sends the 102 report at most once, and never after the
// final status or the first body byte, or after the handler returned.
type hookProgressWriter struct {
	http.ResponseWriter
	mu    sync.Mutex
	final bool
	sent  bool
}

// withHookProgress returns w and r ready to report progress when r asks for
// it, and the function the handler defers to close the window.
func withHookProgress(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *http.Request, func()) {
	if r.Header.Get(hookexec.HookProgressHeader) != "1" {
		return w, r, func() {}
	}
	progress := &hookProgressWriter{ResponseWriter: w}
	ctx := context.WithValue(r.Context(), hookProgressContextKey{}, progress)
	return progress, r.WithContext(ctx), progress.close
}

// reportHookProgress sends the request's 102 report, if it asked for one.
// The decision path calls it on the request's goroutine before it waits on a
// remote scanner.
func reportHookProgress(ctx context.Context) {
	if ctx == nil {
		return
	}
	if progress, ok := ctx.Value(hookProgressContextKey{}).(*hookProgressWriter); ok {
		progress.report()
	}
}

func (w *hookProgressWriter) report() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.final || w.sent {
		return
	}
	w.sent = true
	w.ResponseWriter.WriteHeader(hookexec.HookProgressStatus)
}

func (w *hookProgressWriter) close() {
	w.mu.Lock()
	w.final = true
	w.mu.Unlock()
}

// begin marks the final answer and reports whether this call is the first.
func (w *hookProgressWriter) begin() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	first := !w.final
	w.final = true
	return first
}

func (w *hookProgressWriter) WriteHeader(code int) {
	if code >= 200 {
		w.begin()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *hookProgressWriter) Write(p []byte) (int, error) {
	if w.begin() {
		// A body without a status is a 200. Say so, so a wrapper that
		// recorded the 102 records the final status too.
		w.ResponseWriter.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *hookProgressWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *hookProgressWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
