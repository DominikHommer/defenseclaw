// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package axis

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimePinRefusesBeforeExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "axis")
	content := []byte("inert fixture, never executed")
	if err := os.WriteFile(path, content, 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	valid := hex.EncodeToString(digest[:])
	for _, tc := range []struct {
		name string
		pin  runtimePin
		want string
	}{
		{"missing path", runtimePin{"", valid}, "absolute"},
		{"relative path", runtimePin{"axis", valid}, "absolute"},
		{"missing digest", runtimePin{path, ""}, "reviewed 64-digit"},
		{"malformed digest", runtimePin{path, strings.Repeat("z", 64)}, "reviewed 64-digit"},
		{"mismatch", runtimePin{path, strings.Repeat("0", 64)}, "SHA256 mismatch"},
		{"missing binary", runtimePin{filepath.Join(t.TempDir(), "missing"), valid}, "resolve"},
		{"directory", runtimePin{t.TempDir(), valid}, "regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyRuntime(tc.pin); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wanted refusal containing %q, got %v", tc.want, err)
			}
		})
	}
	if err := verifyRuntime(runtimePin{path, valid}); err != nil {
		t.Fatalf("reviewed inert fixture should verify without execution: %v", err)
	}
	if err := os.WriteFile(path, []byte("changed after review"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntime(runtimePin{path, valid}); err == nil {
		t.Fatal("tampered executable accepted")
	}
}

func TestUnsupportedPlatformsRefuse(t *testing.T) {
	for _, goos := range []string{"windows", "darwin", "freebsd"} {
		if err := requireLinux(goos); !errors.Is(err, errUnsupportedPlatform) {
			t.Fatalf("%s: wanted unsupported platform, got %v", goos, err)
		}
	}
	if err := requireLinux("linux"); err != nil {
		t.Fatal(err)
	}
}

func TestPrivatePlanDropsInheritedEnvironment(t *testing.T) {
	// Synthetic markers only; these tests never inspect real host values.
	t.Setenv("ANTHROPIC_API_KEY", "synthetic-test-marker")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "synthetic-test-marker")
	t.Setenv("HTTP_PROXY", "http://synthetic.invalid")
	t.Setenv("LD_PRELOAD", "/synthetic/unused")
	t.Setenv("AXIS_SOCKET", "/synthetic/unused.sock")
	s, err := newProbeSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.close(); err != nil {
			t.Errorf("cleanup private session: %v", err)
		}
	})
	env := strings.Join(s.environment(), "\n")
	for _, forbidden := range []string{"synthetic-test-marker", "HTTP_PROXY", "LD_PRELOAD", "AXIS_SOCKET", "API_KEY", "OAUTH_TOKEN"} {
		if strings.Contains(env, forbidden) {
			t.Fatalf("inherited setting %q entered probe environment", forbidden)
		}
	}
	if !strings.Contains(env, "HOME="+s.home) || !strings.Contains(env, "PATH=/usr/bin:/bin") {
		t.Fatal("private HOME or fixed system PATH missing")
	}
	payload := filepath.Join(s.workspace, "inert-payload")
	args, err := s.arguments(payload, "literal argument; no shell interpolation")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--socket", s.socket, "run", "--policy", s.policy, "--", payload, "literal argument; no shell interpolation"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("arguments changed: %#v", args)
	}
	if !strings.Contains(s.policyYAML(), "mode: block") || !strings.Contains(s.policyYAML(), "compatibility: hard_requirement") || strings.Contains(s.policyYAML(), "~") {
		t.Fatal("policy must require exact filesystem enforcement, offline networking and explicit private paths")
	}
	if err := os.WriteFile(s.socket, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.arguments(payload); err == nil {
		t.Fatal("existing socket path accepted by standalone workaround")
	}
}

func TestOutputIsBounded(t *testing.T) {
	var output boundedOutput
	input := []byte(strings.Repeat("x", 2*maxOutputBytes))
	if n, err := output.Write(input); err != nil || n != len(input) {
		t.Fatalf("writer did not drain full input: %d, %v", n, err)
	}
	text, truncated := output.snapshot()
	if len(text) != maxOutputBytes || !truncated {
		t.Fatal("output cap or truncation marker missing")
	}
}
