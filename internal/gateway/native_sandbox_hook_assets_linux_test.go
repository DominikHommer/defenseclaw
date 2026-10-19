// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
	"golang.org/x/sys/unix"
)

// Host filesystem/Unix transport only: no agent, namespace, mount or executable.
// This source remains unexecuted until the separate ROOT/Max test gate.
func TestNativeHookAssetsLinuxHeldDirectoryAndNativeCleanupBarrier(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("initial native producer floor refuses host root")
	}
	fixture := newSandboxIngressFixture(t)
	_, spec := nativeHookAssetFake(t)
	lifetime, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	binding, token, err := fixture.store.Mint(sandboxauth.Spec{SandboxID: spec.Identity.ID, SandboxName: spec.Identity.Name, Connector: spec.Harness,
		AgentVersion: spec.HarnessIdentity.Version, HookContractID: spec.HarnessIdentity.HookContract, ExecutionOS: "linux",
		Routes: []sandboxauth.Route{sandboxauth.RouteHook}, Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}, TTL: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	spec.BindingID = binding.ID
	parentPath := t.TempDir()
	if err := os.Chmod(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	owner, err := fixture.api.newNativeSandboxHookAssets(lifetime, spec.Identity, spec.HarnessIdentity, "", binding.ID, token, parent)
	if owner != nil {
		t.Cleanup(func() {
			ctx, done := context.WithTimeout(context.Background(), time.Second)
			defer done()
			_ = owner.Close(ctx)
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	var grant *os.File
	closes := 0
	_, err = owner.prepare(lifetime, spec, []string{"/other", bridgeproto.HookDirectory},
		func(_ context.Context, file *os.File, hook *bridgeproto.Hook) (sandboxruntime.PreparedProcess, error) {
			grant = file
			flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Fatal("inheritable mount handoff")
			}
			fd, err := unix.Openat(int(file.Fd()), "runtime.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			profile := os.NewFile(uintptr(fd), "fixed-public-runtime")
			raw, readErr := io.ReadAll(io.LimitReader(profile, 4097))
			if err := profile.Close(); err != nil {
				t.Fatal(err)
			}
			decoded, decodeErr := hookexec.DecodeNativeSandboxProfile(raw)
			digest := sha256.Sum256(raw)
			if readErr != nil || decodeErr != nil || decoded.SessionID != spec.Identity.ID || decoded.Connector != spec.Harness || hook.SessionID != spec.Identity.ID || hook.ReadIndex != 1 || hook.ProfileDigest != "sha256:"+hex.EncodeToString(digest[:]) {
				t.Fatal("profile/typed mount differs from owned binding")
			}
			return &nativeHookAssetFakeProcess{close: func(context.Context) error {
				closes++
				if closes == 1 {
					return errors.New("fixed native wait uncertainty")
				}
				return grant.Close()
			}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parentPath)
	if err != nil || len(entries) != 1 {
		t.Fatal("unexpected created root")
	}
	rootPath := filepath.Join(parentPath, entries[0].Name())
	for leaf, mode := range map[string]os.FileMode{"runtime.json": 0o400, "ingress.sock": 0o600} {
		info, err := os.Lstat(filepath.Join(rootPath, leaf))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("incorrect fixed private entry mode")
		}
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", fmt.Sprintf("/proc/self/fd/%d/ingress.sock", grant.Fd()))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if status, _ := nativeHookPost(t, client, "/api/v1/claudecode/hook"); status != http.StatusOK {
		t.Fatalf("shared hook dispatch %d", status)
	}
	if err := owner.Close(lifetime); err == nil {
		t.Fatal("uncertain native wait was released")
	}
	if status, _ := nativeHookPost(t, client, "/api/v1/claudecode/hook"); status != http.StatusServiceUnavailable {
		t.Fatal("endpoint admission was not sealed before failed native cleanup")
	}
	if children, err := os.ReadDir(rootPath); err != nil || len(children) != 2 {
		t.Fatal("premature deletion before native cleanup")
	}
	if err := owner.Close(lifetime); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Match(token); err == nil {
		t.Fatal("host-only binding not durably revoked before release")
	}
	if entries, err := os.ReadDir(parentPath); err != nil || len(entries) != 0 {
		t.Fatal("owned hook residue after confirmed cleanup")
	}
}

func TestNativeHookAssetsLinuxUncertainCloseRetainsPinAndStopsCleanup(t *testing.T) {
	file := new(os.File)
	calls := 0
	files := &nativeHookLinuxFiles{root: file, closeNative: func(*os.File) error { calls++; return errors.New("fixed uncertain close") }}
	if files.closeFile(&files.root) == nil || files.root != file {
		t.Fatal("uncertain handle lost")
	}
	if files.close() == nil || calls != 1 || files.root != file {
		t.Fatal("uncertain close retried or residue released")
	}
}
