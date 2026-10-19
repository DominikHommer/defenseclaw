// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// All process/endpoint/file actions below are fakes. These tests do not open
// sockets, create a filesystem fixture, launch a child or invoke native code.
type nativeHookAssetFakeProcess struct {
	close  func(context.Context) error
	launch func(context.Context, sandboxruntime.Spec) (sandboxruntime.Instance, error)
}

func (p *nativeHookAssetFakeProcess) Close(ctx context.Context) error { return p.close(ctx) }
func (p *nativeHookAssetFakeProcess) Launch(ctx context.Context, spec sandboxruntime.Spec) (sandboxruntime.Instance, error) {
	if p.launch == nil {
		return sandboxruntime.Instance{}, errors.New("unexpected launch")
	}
	return p.launch(ctx, spec)
}

func nativeHookAssetFake(t *testing.T) (*nativeSandboxHookAssets, sandboxruntime.Spec) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	artifact := sandboxruntime.ArtifactIdentity{Kind: sandboxruntime.ExecutableBundle, Digest: "sha256:" + strings.Repeat("a", 64)}
	identity := sandboxruntime.SessionIdentity{Owner: "test-owner", ID: "host-selected-session", Name: "native-test",
		Runtime: sandboxruntime.RuntimeIdentity{Runtime: sandboxruntime.Axis, Backend: "mxc", Driver: "bubblewrap", HostOS: "linux", ExecutionOS: "linux", Architecture: "amd64", Version: "pinned", Artifact: artifact}}
	harness := sandboxruntime.HarnessIdentity{Version: "2.1.292", HookContract: "claudecode-hooks-v1", Artifact: artifact}
	assets := &nativeSandboxHookAssets{op: make(chan struct{}, 1), identity: identity, harness: harness, lifetime: ctx,
		connector: "claudecode", contract: harness.HookContract, bindingID: "host-selected-binding", digest: "sha256:" + strings.Repeat("b", 64),
		admission: func() bool { return true }, duplicate: func() (*os.File, error) { return new(os.File), nil },
		seal: func() {}, revoke: func(context.Context) error { return nil }, drain: func(context.Context) error { return nil }, release: func() error { return nil }}
	return assets, sandboxruntime.Spec{Identity: identity, Harness: "claudecode", HarnessIdentity: harness, BindingID: assets.bindingID, Offline: true}
}

func TestNativeHookAssetsCleanupOrderAndRetry(t *testing.T) {
	for _, stage := range []string{"native", "drain", "revoke"} {
		t.Run(stage, func(t *testing.T) {
			assets, _ := nativeHookAssetFake(t)
			var calls []string
			failed := false
			step := func(name string) error {
				calls = append(calls, name)
				if name == stage && !failed {
					failed = true
					return errors.New("fixed uncertainty")
				}
				return nil
			}
			assets.revoke = func(context.Context) error { return step("revoke") }
			assets.seal = func() { calls = append(calls, "seal") }
			assets.process = &nativeHookAssetFakeProcess{close: func(context.Context) error { return step("native") }}
			assets.drain = func(context.Context) error { return step("drain") }
			assets.release = func() error { return step("release") }
			if assets.Close(context.Background()) == nil || assets.released {
				t.Fatal("uncertain cleanup released assets")
			}
			for _, call := range calls {
				if call == "release" {
					t.Fatal("release before successful owned cleanup")
				}
			}
			if err := assets.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			var expected []string
			switch stage {
			case "native":
				expected = []string{"seal", "native", "seal", "native", "revoke", "drain", "release"}
			case "drain":
				expected = []string{"seal", "native", "revoke", "drain", "seal", "revoke", "drain", "release"}
			case "revoke":
				expected = []string{"seal", "native", "revoke", "drain", "seal", "revoke", "release"}
			}
			if !reflect.DeepEqual(calls, expected) {
				t.Fatalf("cleanup order %v", calls)
			}
		})
	}
}

func TestNativeHookAssetsRetainsPartialProcessAndTypedMountBinding(t *testing.T) {
	assets, spec := nativeHookAssetFake(t)
	closed := false
	process := &nativeHookAssetFakeProcess{close: func(context.Context) error { closed = true; return nil }}
	owner, err := assets.prepare(context.Background(), spec, []string{"/reviewed", bridgeproto.HookDirectory},
		func(_ context.Context, file *os.File, hook *bridgeproto.Hook) (sandboxruntime.PreparedProcess, error) {
			if file == nil || hook.SessionID != spec.Identity.ID || hook.ReadIndex != 1 || hook.ProfileDigest != assets.digest {
				t.Fatal("different typed mount authority")
			}
			return process, errors.New("fixed partial preparation")
		})
	if owner != assets || err == nil || assets.complete {
		t.Fatal("partial preparation reported success")
	}
	assets.release = func() error {
		if !closed {
			t.Fatal("native custody not closed")
		}
		return nil
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNativeHookAssetsCloseCancelsInFlightPreparationBeforeRelease(t *testing.T) {
	assets, spec := nativeHookAssetFake(t)
	entered, sealed, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	assets.seal = func() { once.Do(func() { close(sealed) }) }
	assets.release = func() error {
		select {
		case <-returned:
		default:
			t.Error("released while factory still owned the duplicate")
		}
		return nil
	}
	prepared := make(chan error, 1)
	go func() {
		_, err := assets.prepare(context.Background(), spec, []string{bridgeproto.HookDirectory},
			func(ctx context.Context, _ *os.File, _ *bridgeproto.Hook) (sandboxruntime.PreparedProcess, error) {
				close(entered)
				<-ctx.Done()
				close(returned)
				return &nativeHookAssetFakeProcess{close: func(context.Context) error { return nil }}, ctx.Err()
			})
		prepared <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("factory did not start")
	}
	cleanup, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := assets.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sealed:
	default:
		t.Fatal("admission was not sealed")
	}
	select {
	case err := <-prepared:
		if err == nil {
			t.Fatal("late factory success escaped closed owner")
		}
	case <-cleanup.Done():
		t.Fatal("factory ownership did not return")
	}
	if assets.complete {
		t.Fatal("closed preparation remained launchable")
	}
}

func TestNativeHookAssetsCloseRacesUnconsumedHandoffWithoutCallbackRace(t *testing.T) {
	assets, spec := nativeHookAssetFake(t)
	entered, sealed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	assets.seal = func() { once.Do(func() { close(sealed) }) }
	released := false
	assets.release = func() error { released = true; return nil }
	prepared := make(chan error, 1)
	go func() {
		_, err := assets.prepare(context.Background(), spec, []string{bridgeproto.HookDirectory},
			func(ctx context.Context, _ *os.File, _ *bridgeproto.Hook) (sandboxruntime.PreparedProcess, error) {
				close(entered)
				<-ctx.Done()
				<-sealed
				// The exclusive duplicate was not consumed. prepare replaces the
				// release callback while Close waits for the operation token.
				return nil, ctx.Err()
			})
		prepared <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("factory did not enter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// The fake is a zero os.File: its Close returns ErrInvalid without an OS
	// handle operation. That uncertainty must retain the resource callback.
	if err := assets.Close(ctx); err == nil || released {
		t.Fatal("unconsumed uncertain file was released")
	}
	select {
	case err := <-prepared:
		if err == nil {
			t.Fatal("unconsumed handoff reported success")
		}
	case <-ctx.Done():
		t.Fatal("factory did not return")
	}
	if err := assets.Close(ctx); err == nil || released {
		t.Fatal("uncertain close lost sticky custody")
	}
}

func TestNativeHookAssetsRejectsIdentityAndAdmissionBeforeAssetHandoff(t *testing.T) {
	for _, change := range []func(*nativeSandboxHookAssets, *sandboxruntime.Spec){
		func(_ *nativeSandboxHookAssets, s *sandboxruntime.Spec) { s.Identity.ID = "guest-selected" },
		func(_ *nativeSandboxHookAssets, s *sandboxruntime.Spec) {
			s.HarnessIdentity.Artifact.Digest = "sha256:" + strings.Repeat("c", 64)
		},
		func(a *nativeSandboxHookAssets, _ *sandboxruntime.Spec) { a.admission = func() bool { return false } },
	} {
		assets, spec := nativeHookAssetFake(t)
		change(assets, &spec)
		assets.duplicate = func() (*os.File, error) { t.Fatal("duplicated before owner admission"); return nil, nil }
		_, err := assets.prepare(context.Background(), spec, []string{bridgeproto.HookDirectory}, func(context.Context, *os.File, *bridgeproto.Hook) (sandboxruntime.PreparedProcess, error) {
			t.Fatal("factory ran")
			return nil, nil
		})
		if err == nil {
			t.Fatal("foreign or revoked owner admitted")
		}
	}
}

func TestNativeHookAssetsDirectoryTerminalObservation(t *testing.T) {
	for _, tc := range []struct {
		name              string
		first, tail       []string
		firstErr, tailErr error
		empty, accepted   bool
	}{
		{"nonempty nil then EOF", []string{"runtime.json", "ingress.sock"}, nil, nil, io.EOF, false, true},
		{"nonempty EOF", []string{"ingress.sock", "runtime.json"}, nil, io.EOF, nil, false, true},
		{"late third entry", []string{"runtime.json", "ingress.sock"}, []string{"replacement"}, nil, nil, false, false},
		{"nonterminal empty", []string{"runtime.json", "ingress.sock"}, nil, nil, nil, false, false},
		{"duplicate", []string{"runtime.json", "runtime.json"}, nil, io.EOF, nil, false, false},
		{"unknown", []string{"runtime.json", "other"}, nil, io.EOF, nil, false, false},
		{"empty", nil, nil, io.EOF, nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := exactNativeHookEntries(func(n int) ([]string, error) {
				calls++
				if calls == 1 {
					if n != 3 {
						t.Fatal("first bound")
					}
					return tc.first, tc.firstErr
				}
				if calls != 2 || n != 1 {
					t.Fatal("tail bound")
				}
				return tc.tail, tc.tailErr
			}, tc.empty)
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v err=%v", tc.accepted, err)
			}
		})
	}
}
