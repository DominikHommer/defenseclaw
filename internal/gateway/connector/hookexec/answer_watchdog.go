// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"io"
	"sync"
	"time"
)

// answerWatchdogLogWait bounds the hook-failure log line the watchdog writes
// after its answer: a stalled disk must not hold the process past it.
var answerWatchdogLogWait = 100 * time.Millisecond

// answerWatchdog makes the answer budget of a tool call hold when the hook
// process itself runs late. On a host that lifecycle work saturates (the
// Windows attestation repair of GAP-0155 and GAP-0167) the call's own
// goroutines can be held past the budget in work that no context ends: a
// service-manager query, the account and session lookups, a file read, or
// simply no CPU. The deny of such a call came a second or more after the
// budget.
//
// The watchdog renders the call's fail-closed answer (failNoAnswer: closed
// for a managed hook, the account's fail mode for a per-user hook) when the
// call starts, and at the answer deadline writes it and ends the process
// (Options.Exit), unless the call's own result is out or the gateway's
// decision, or its report that it waits on a remote scanner, is in. Until
// then the call's output is held in memory, so exactly one answer reaches the
// agent. On Windows the watchdog waits on its own thread at the highest
// priority of the process (answerDeadlineWaiter), so ordinary-priority work
// that fills the CPU does not delay it. It never allows a call: its answer is
// the one the call gives when its gateway does not answer in time.
type answerWatchdog struct {
	mu       sync.Mutex
	finished bool
	fired    bool

	stdout, stderr io.Writer
	out, err       bytes.Buffer

	fallbackOut, fallbackErr []byte
	fallbackCode             int
	logFailure               func()
	exit                     func(int)

	waiter *answerDeadlineWaiter
}

// startAnswerWatchdog arms the watchdog of a tool call whose answer is due at
// deadline. It points opts at the held output; Run returns through finish.
func startAnswerWatchdog(opts *Options, sp spec, failMode string, deadline time.Time) *answerWatchdog {
	w := &answerWatchdog{stdout: opts.Stdout, stderr: opts.Stderr, exit: opts.Exit, waiter: newAnswerDeadlineWaiter()}
	var fallbackOut, fallbackErr bytes.Buffer
	rendered := *opts
	rendered.Stdout, rendered.Stderr = &fallbackOut, &fallbackErr
	// Rendering only: the failure is logged when the watchdog answers.
	rendered.Home = ""
	w.fallbackCode = failNoAnswer(rendered, sp, failMode)
	w.fallbackOut, w.fallbackErr = fallbackOut.Bytes(), fallbackErr.Bytes()
	logged := *opts
	w.logFailure = func() {
		if logged.ManagedEnterprise {
			logHookFailure(logged, sp, managedGatewayNoAnswerReason, "transport", "closed")
			return
		}
		logHookFailure(logged, sp, perUserGatewayNoAnswerReason, "transport", failMode)
	}
	opts.Stdout, opts.Stderr = &w.out, &w.err
	opts.answerWatch = w
	go w.watch(deadline)
	return w
}

func (w *answerWatchdog) watch(deadline time.Time) {
	if !w.waiter.wait(deadline) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return
	}
	w.fired = true
	_, _ = w.stderr.Write(w.fallbackErr)
	_, _ = w.stdout.Write(w.fallbackOut)
	if w.exit == nil {
		w.logFailure()
		return
	}
	logged := make(chan struct{})
	go func() {
		defer close(logged)
		w.logFailure()
	}()
	timer := time.NewTimer(answerWatchdogLogWait)
	select {
	case <-logged:
	case <-timer.C:
	}
	timer.Stop()
	// Production exits here; the lock is never released, so the call's own
	// output cannot follow the answer.
	w.exit(w.fallbackCode)
}

// answered stands the watchdog down: the gateway's decision, or its report
// that it waits on a remote scanner, is in. Safe on a nil watchdog.
func (w *answerWatchdog) answered() {
	if w != nil {
		w.waiter.cancel()
	}
}

// finish writes the call's own result unless the watchdog already answered,
// and returns the exit status of the answer the agent got.
func (w *answerWatchdog) finish(code int) int {
	w.waiter.cancel()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return w.fallbackCode
	}
	w.finished = true
	_, _ = w.stderr.Write(w.err.Bytes())
	_, _ = w.stdout.Write(w.out.Bytes())
	return code
}
