// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package agentprocess

import (
	"errors"
	"runtime"
	"testing"
)

func TestEndedOnlyForAProvablyEndedProcess(t *testing.T) {
	lookup := func(pid int) (Process, error) {
		switch pid {
		case 10:
			return Process{PID: 10, Start: 5, Boot: "b"}, nil
		case 11:
			return Process{PID: 11, Start: 5, Boot: "b", Exited: true}, nil
		case 12:
			return Process{}, errors.New("permission denied")
		}
		return Process{}, errNotFound
	}
	goos := runtime.GOOS
	for identity, want := range map[string]bool{
		goos + ":b:10:5":     false, // running
		goos + ":b:10:6":     true,  // the ID was reused
		goos + ":b:11:5":     true,  // exited
		goos + ":b:13:5":     true,  // no such process
		goos + ":b:12:5":     false, // lookup failed: unknown
		goos + ":other:10:5": true,  // another boot
		goos + "::10:5":      false, // boot unknown: cannot compare
		"plan9:b:10:5":       true,  // another operating system
		"":                   false,
		goos + ":b:x:5":      false,
		goos + ":b:10":       false,
	} {
		if got := endedFrom(lookup, "b", identity); got != want {
			t.Errorf("endedFrom(%q) = %t, want %t", identity, got, want)
		}
	}
	if endedFrom(lookup, "", goos+":b:10:5") {
		t.Error("an unknown current boot proved another boot")
	}
}

func TestSelfIsNotEnded(t *testing.T) {
	self := Self()
	if self == "" {
		t.Skip("process lookups are not supported here")
	}
	if Ended(self) {
		t.Fatalf("this process (%s) reads as ended", self)
	}
}
