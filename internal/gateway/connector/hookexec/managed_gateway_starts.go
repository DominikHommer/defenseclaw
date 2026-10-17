// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"io"
	"sync"
	"syscall"
	"time"
)

// errGatewayStartFailing ends a hook request early when the managed gateway
// service keeps failing to start. Its socket stays open (systemd holds it
// and restarts the service without a limit), so without this a hook waits
// its whole budget, about 30 seconds per prompt, before failing closed.
var errGatewayStartFailing = errors.New("the managed gateway service keeps failing to start")

// errGatewayRestarting ends a managed hook request whose gateway is still
// stopping or starting when the restart budget ends. The call fails closed:
// it is blocked, never allowed.
var errGatewayRestarting = errors.New("the managed gateway service is restarting")

// managedGatewayRestartingReason is the hook-failure reason of a managed
// hook that failed closed because its gateway was restarting (a package
// upgrade, a rollback, a configuration change that needs a restart) for
// longer than managedGatewayRestartBudget.
const managedGatewayRestartingReason = "enterprise_managed_gateway_restarting"

// managedGatewayRestartBudget is how long, from the start of the hook, a
// managed hook keeps trying a gateway that is restarting: it sends the call
// again when the gateway refused the connection or dropped it unanswered,
// and stops waiting on a call queued in a socket while the service is not
// running. After it the call fails closed. A restart that is over by then
// is invisible to the agent, which is answered from the policy the gateway
// loads at start, the last one applied; a longer one blocks each call
// within about 3 seconds instead of holding it for the hook's whole budget
// (#1278). A gateway that is up and evaluating keeps the full budget.
const managedGatewayRestartBudget = 3 * time.Second

// managedGatewayRestartRetryDelay is the pause between two tries.
var managedGatewayRestartRetryDelay = 200 * time.Millisecond

// managedGatewayRestartDeadline is when a managed hook started at startedAt
// stops waiting for a restarting gateway; zero (no restart handling) for a
// per-user or Secure Client hook, which keep their behavior.
func managedGatewayRestartDeadline(opts Options, startedAt time.Time) time.Time {
	if !opts.ManagedEnterprise || opts.SecureClient || startedAt.IsZero() {
		return time.Time{}
	}
	return startedAt.Add(managedGatewayRestartBudget)
}

// gatewayRestartShaped reports a transport error that a gateway restart
// causes: the service is not running, nothing accepts the connection, or
// the connection closed before any answer. Any other peer-verification
// failure is final: a listener that is not the gateway gets no second try.
func gatewayRestartShaped(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errManagedGatewayNotRunning) {
		return true
	}
	if errors.Is(err, errManagedGatewayPeerUnverified) || errors.Is(err, errInvalidHookRequest) {
		return false
	}
	return connectionRefused(err) || connectionReset(err) || errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// awaitManagedGatewayRestart waits before the next try of a call that failed
// because its gateway is restarting, and reports whether to try again: only
// for a restart-shaped error, and only while the next try still starts
// before deadline.
func awaitManagedGatewayRestart(ctx context.Context, deadline time.Time, err error) bool {
	if deadline.IsZero() || ctx.Err() != nil || !gatewayRestartShaped(err) {
		return false
	}
	delay := managedGatewayRestartRetryDelay
	if !time.Now().Add(delay).Before(deadline) {
		return false
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// gatewayServiceState is the service manager's view of the managed gateway.
type gatewayServiceState struct {
	Active   string // ActiveState: active, activating, failed, ...
	Sub      string // SubState: running, start, auto-restart, ...
	Restarts int    // NRestarts
}

// gatewayStartWatchInterval is how often a waiting hook asks the service
// manager about the gateway; gatewayRunningWatchInterval once it runs.
var (
	gatewayStartWatchInterval   = time.Second
	gatewayRunningWatchInterval = 2 * time.Second
)

// watchManagedGatewayStarts returns ctx, ended with errGatewayStartFailing
// once the standalone gateway service is seen failing a start that began
// while this hook waited, or with errGatewayRestarting when the service is
// still not running at deadline (the call sits in the socket systemd holds
// across the restart). stop ends the watch (call it once the response
// arrives); release frees ctx. Off Linux, or outside the standalone
// profile, ctx is returned unchanged.
func watchManagedGatewayStarts(ctx context.Context, opts Options, deadline time.Time) (watched context.Context, stop, release func()) {
	probe := standaloneGatewayServiceProbe
	if !opts.ManagedEnterprise || !opts.ManagedStandalone || probe == nil {
		return ctx, func() {}, func() {}
	}
	watched, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	var once sync.Once
	stop = func() { once.Do(func() { close(done) }) }
	go watchGatewayStarts(watched, done, cancel, probe, gatewayStartWatchInterval, deadline)
	return watched, stop, func() { stop(); cancel(nil) }
}

// watchGatewayStarts polls probe until the watch stops, the service manager
// cannot answer, or the request is ended: by a restart counted after the
// first poll that ends in another failure, or by a service that is still
// stopping or starting at deadline (zero: never). A single crash followed
// by a good start, or a running gateway whose answer is just slow, keeps
// the request waiting; a running gateway is still watched, since it can
// stop under a call it accepted.
func watchGatewayStarts(
	ctx context.Context,
	done <-chan struct{},
	cancel context.CancelCauseFunc,
	probe func(context.Context) (gatewayServiceState, error),
	interval time.Duration,
	deadline time.Time,
) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	baseline := -1
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-timer.C:
		}
		state, err := probe(ctx)
		if err != nil {
			// No answer from the service manager: keep waiting as before.
			return
		}
		if baseline < 0 {
			baseline = state.Restarts
		}
		next := interval
		switch {
		case state.Active == "failed":
			cancel(errGatewayStartFailing)
			return
		case state.Restarts > baseline && state.Sub == "auto-restart":
			cancel(errGatewayStartFailing)
			return
		case state.Active == "active":
			next = max(interval, gatewayRunningWatchInterval)
		case !deadline.IsZero():
			// Stopping, starting or stopped: the call waits in the socket.
			left := time.Until(deadline)
			if left <= 0 {
				cancel(errGatewayRestarting)
				return
			}
			next = min(interval, left)
		}
		timer.Reset(next)
	}
}
