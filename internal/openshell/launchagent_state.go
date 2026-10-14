// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// LaunchAgentState contains the service fields needed to judge an on-demand
// launchd job. A loaded job can be idle before its first start or after a
// clean exit.
type LaunchAgentState struct {
	State, ExitReason, ExitCode, SpawnError string
	Runs                                    int
}

// ParseLaunchAgentState reads the service fields from launchctl print output.
func ParseLaunchAgentState(raw []byte) LaunchAgentState {
	var s LaunchAgentState
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		switch key {
		case "state":
			if s.State == "" {
				s.State = value
			}
		case "runs":
			s.Runs, _ = strconv.Atoi(value)
		case "last exit reason":
			s.ExitReason = value
		case "last exit code":
			s.ExitCode = value
		case "last spawn error":
			s.SpawnError = value
		}
	}
	return s
}

// Failure reports a failed start, allowing a cleanly idle on-demand job.
// A currently running job is healthy even if launchd kept an older exit reason.
func (s LaunchAgentState) Failure(expectedRunning bool) string {
	if s.State == "running" {
		return ""
	}
	if strings.Contains(strings.ToUpper(s.ExitReason), "CODESIGN") || strings.Contains(strings.ToUpper(s.SpawnError), "CODESIGN") {
		return "last start was killed for code signing (" + strings.TrimSpace(s.ExitReason+" "+s.SpawnError) + ")"
	}
	if s.SpawnError != "" {
		return "last spawn error: " + s.SpawnError
	}
	if s.ExitCode != "" && s.ExitCode != "0" && s.ExitCode != "(never exited)" {
		return "last exit code " + s.ExitCode
	}
	if expectedRunning {
		return "loaded but not running when it must be running"
	}
	if s.Runs > 0 && s.ExitCode == "(never exited)" {
		return "loaded but not running after a failed start"
	}
	return ""
}

// CheckIDManagedLaunchAgent is the managed Mac's current-user gateway job.
const CheckIDManagedLaunchAgent = "managed-openshell-launchagent"

const managedLaunchAgentLabel = "com.cisco.defenseclaw.openshell-gateway"

// ManagedLaunchAgentCheck reads only the current user's loaded gateway job.
// The administrator's enterprise repair owns all launchctl mutations.
func (d *Doctor) ManagedLaunchAgentCheck(ctx context.Context) *Check {
	if !d.Managed || d.GOOS != "darwin" {
		return nil
	}
	d.defaults()
	target := "gui/" + strconv.Itoa(d.Geteuid()) + "/" + managedLaunchAgentLabel
	raw, err := d.Runner.Output(ctx, Command{Name: "launchctl", Args: []string{"print", target}, Timeout: 10 * time.Second})
	if err != nil && launchAgentMissing(raw, err) {
		return nil
	}
	c := &Check{ID: CheckIDManagedLaunchAgent, Title: "OpenShell LaunchAgent"}
	if err != nil {
		c.Status, c.Detail = StatusWarn, "could not inspect "+target+": "+err.Error()
		return c
	}
	state := ParseLaunchAgentState(raw)
	if state.State == "" {
		c.Status, c.Detail = StatusWarn, "launchctl returned no service state for "+target
		return c
	}
	if why := state.Failure(false); why != "" {
		c.Status, c.Detail = StatusFail, target+" is "+why
		c.Fix = &Fix{Summary: "ask your administrator to repair this computer's sandbox LaunchAgent", Command: "sudo defenseclaw-gateway enterprise macos repair", Sudo: true}
		return c
	}
	c.Status = StatusPass
	if state.State == "running" {
		c.Detail = "running"
	} else {
		c.Detail = "loaded and idle; starts with the next sandbox command"
	}
	return c
}

func launchAgentMissing(raw []byte, err error) bool {
	message := strings.ToLower(string(raw) + " " + err.Error())
	return strings.Contains(message, "could not find service") || strings.Contains(message, "could not find domain") || strings.Contains(message, "no such process")
}
