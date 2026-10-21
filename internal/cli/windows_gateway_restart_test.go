// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeWindowsGatewayService plays a sequence of SCM states: each query
// takes the next one and repeats the last. stop and start record the call
// and move the service to the state the SCM reports next.
type fakeWindowsGatewayService struct {
	states    []windowsServiceState
	afterStop []windowsServiceState
	stopErr   error
	calls     []string
}

func (f *fakeWindowsGatewayService) state() (windowsServiceState, error) {
	state := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return state, nil
}

func (f *fakeWindowsGatewayService) stop() error {
	f.calls = append(f.calls, "stop")
	if f.stopErr != nil {
		return f.stopErr
	}
	f.states = f.afterStop
	return nil
}

func (f *fakeWindowsGatewayService) start() error {
	f.calls = append(f.calls, "start")
	f.states = []windowsServiceState{windowsServiceStartPending}
	return nil
}

// A gateway whose process runs or is starting may hold the old credential or
// config, so it is restarted; StartPending is waited out first (the SCM
// refuses a stop while a service starts). Only a stopped gateway, or one
// stopping on its own, needs no restart.
func TestWindowsGatewayRestartTreatsAStartingGatewayAsLive(t *testing.T) {
	stopped := []windowsServiceState{windowsServiceStopPending, windowsServiceStopped}
	for _, tc := range []struct {
		name      string
		states    []windowsServiceState
		restarted bool
	}{
		{"running", []windowsServiceState{windowsServiceRunning}, true},
		{"start pending, then running", []windowsServiceState{windowsServiceStartPending, windowsServiceStartPending, windowsServiceRunning}, true},
		{"paused", []windowsServiceState{windowsServicePaused}, true},
		{"continue pending, then running", []windowsServiceState{windowsServiceContinuePending, windowsServiceRunning}, true},
		{"pause pending, then paused", []windowsServiceState{windowsServicePausePending, windowsServicePaused}, true},
		{"start pending, then stopped (the start failed)", []windowsServiceState{windowsServiceStartPending, windowsServiceStopped}, false},
		{"stopped", []windowsServiceState{windowsServiceStopped}, false},
		{"stop pending, then stopped", stopped, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeWindowsGatewayService{states: tc.states, afterStop: stopped}
			restarted, err := restartWindowsGatewayService(service, "DefenseClawGateway", time.Second, time.Millisecond)
			if err != nil || restarted != tc.restarted {
				t.Fatalf("restarted = %v, %v; want %v", restarted, err, tc.restarted)
			}
			want := ""
			if tc.restarted {
				want = "stop,start"
			}
			if got := strings.Join(service.calls, ","); got != want {
				t.Fatalf("SCM calls = %q, want %q", got, want)
			}
		})
	}
}

// A gateway that stays in StartPending, or does not stop, is restart_failed:
// never a success with no restart.
func TestWindowsGatewayRestartFailsWhenItCannotRestart(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service *fakeWindowsGatewayService
		want    string
	}{
		{"stuck starting", &fakeWindowsGatewayService{states: []windowsServiceState{windowsServiceStartPending}}, "stayed in service state 2"},
		{"stuck stopping after the stop", &fakeWindowsGatewayService{states: []windowsServiceState{windowsServiceRunning}, afterStop: []windowsServiceState{windowsServiceStopPending}}, "stayed in service state 3"},
		{"stop refused", &fakeWindowsGatewayService{states: []windowsServiceState{windowsServiceRunning}, stopErr: errors.New("access denied")}, "stop DefenseClawGateway: access denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restarted, err := restartWindowsGatewayService(tc.service, "DefenseClawGateway", 20*time.Millisecond, time.Millisecond)
			if restarted || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("restarted = %v, %v; want an error naming %q", restarted, err, tc.want)
			}
		})
	}
}

// The bundle receipt and restore read a gateway in StartPending as running
// (its process exists); a stopped or stopping one is not.
func TestWindowsServiceProcessLive(t *testing.T) {
	for state, live := range map[windowsServiceState]bool{
		windowsServiceStopped: false, windowsServiceStopPending: false,
		windowsServiceStartPending: true, windowsServiceRunning: true,
		windowsServiceContinuePending: true, windowsServicePausePending: true, windowsServicePaused: true,
	} {
		if got := windowsServiceProcessLive(state); got != live {
			t.Fatalf("state %d live = %v, want %v", state, got, live)
		}
	}
}
