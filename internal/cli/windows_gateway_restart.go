// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"time"
)

// windowsServiceState is an SCM service state (SERVICE_STOPPED 1 to
// SERVICE_PAUSED 7, the values of golang.org/x/sys/windows/svc.State). The
// restart decision is portable so every state is tested on each OS.
type windowsServiceState uint32

const (
	windowsServiceStopped         windowsServiceState = 1
	windowsServiceStartPending    windowsServiceState = 2
	windowsServiceStopPending     windowsServiceState = 3
	windowsServiceRunning         windowsServiceState = 4
	windowsServiceContinuePending windowsServiceState = 5
	windowsServicePausePending    windowsServiceState = 6
	windowsServicePaused          windowsServiceState = 7
)

// windowsServiceProcessLive reports a service whose process runs, or is
// starting, and so may hold what it read before a change: every state but
// Stopped and StopPending (a stopping process exits, and the next start
// reads the change). StartPending is a process that already runs.
func windowsServiceProcessLive(state windowsServiceState) bool {
	return state != windowsServiceStopped && state != windowsServiceStopPending
}

// windowsServiceSettling reports a transition the SCM finishes by itself.
func windowsServiceSettling(state windowsServiceState) bool {
	switch state {
	case windowsServiceStartPending, windowsServiceStopPending, windowsServiceContinuePending, windowsServicePausePending:
		return true
	}
	return false
}

// windowsGatewayServiceControl is the SCM view of the gateway service the
// restart drives.
type windowsGatewayServiceControl interface {
	state() (windowsServiceState, error)
	stop() error
	start() error
}

// restartWindowsGatewayService restarts the gateway service so a new process
// reads a changed credential or config. restarted is false only when no
// process was live (stopped, or stopping on its own): the next start reads
// the change. A pending transition is waited out first, so a gateway caught
// in StartPending is restarted once it runs rather than taken for stopped,
// and one that does not settle, stop or start within timeout is an error,
// never a success without a restart.
func restartWindowsGatewayService(service windowsGatewayServiceControl, name string, timeout, poll time.Duration) (bool, error) {
	state, err := waitWindowsServiceState(service, name, timeout, poll, func(state windowsServiceState) bool { return !windowsServiceSettling(state) })
	if err != nil {
		return false, err
	}
	if !windowsServiceProcessLive(state) {
		return false, nil
	}
	if err := service.stop(); err != nil {
		return false, fmt.Errorf("stop %s: %w", name, err)
	}
	if _, err := waitWindowsServiceState(service, name, timeout, poll, func(state windowsServiceState) bool { return state == windowsServiceStopped }); err != nil {
		return false, err
	}
	if err := service.start(); err != nil {
		return false, fmt.Errorf("start %s: %w", name, err)
	}
	return true, nil
}

// waitWindowsServiceState polls the service until done accepts its state.
func waitWindowsServiceState(service windowsGatewayServiceControl, name string, timeout, poll time.Duration, done func(windowsServiceState) bool) (windowsServiceState, error) {
	deadline := time.Now().Add(timeout)
	for {
		state, err := service.state()
		if err != nil {
			return 0, err
		}
		if done(state) {
			return state, nil
		}
		if time.Now().After(deadline) {
			return state, fmt.Errorf("%s stayed in service state %d for %s", name, state, timeout)
		}
		time.Sleep(poll)
	}
}
