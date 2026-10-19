// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

type fakeNativeModelChannel struct {
	identity  sandboxruntime.SessionIdentity
	authority sandboxruntime.PolicyAuthorityBinding
	seal      func(context.Context) error
	close     func(context.Context) error
}

func (f *fakeNativeModelChannel) SealAndQuiesce(ctx context.Context) error { return f.seal(ctx) }
func (f *fakeNativeModelChannel) Close(ctx context.Context) error          { return f.close(ctx) }
func (f *fakeNativeModelChannel) nativeModelLeaseBinding() (sandboxruntime.SessionIdentity, sandboxruntime.PolicyAuthorityBinding) {
	return f.identity, f.authority
}

func nativeModelCustodyIdentity() sandboxruntime.SessionIdentity {
	artifact := sandboxruntime.ArtifactIdentity{
		Kind: sandboxruntime.ExecutableBundle, Digest: "sha256:" + strings.Repeat("a", 64),
	}
	return sandboxruntime.SessionIdentity{
		Owner: "host-owner", ID: "host-model-session", Name: "model-session",
		Runtime: sandboxruntime.RuntimeIdentity{
			Runtime: sandboxruntime.Axis, Backend: "mxc", Driver: "bubblewrap",
			HostOS: "linux", ExecutionOS: "linux", Architecture: "amd64",
			Version: "pinned", Artifact: artifact,
		},
	}
}

func publishNativeModelFixtureGeneration(s *Sidecar, generation uint64) error {
	next := cloneConfig(s.currentConfig())
	next.OpenShell.Egress.Block = append(next.OpenShell.Egress.Block, "fixed.example")
	applied := s.publishConfig(next)
	s.publishGeneration(&Generation{Config: applied, ConfigGen: generation,
		Digest: "sha256:" + strings.Repeat("a", 64)})
	return nil
}

func publishNextNativeModelFixture(s *Sidecar) error {
	return publishNativeModelFixtureGeneration(s, 987654)
}

func TestNativeModelCustodyPublicationOrder(t *testing.T) {
	s := sandboxPublicationFixture(t)
	var order []string
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error {
		order = append(order, "host-revoke")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	model := &fakeNativeModelChannel{
		seal:  func(context.Context) error { order = append(order, "seal"); return nil },
		close: func(context.Context) error { order = append(order, "model-drain"); return nil },
	}
	identity := nativeModelCustodyIdentity()
	model.identity, model.authority = identity, owner.current()
	wrongAuthority := owner.current()
	wrongAuthority.Generation++
	if err := owner.retainNativeModelLease(identity, wrongAuthority, model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("registered a model lease under a different publication")
	}
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { order = append(order, "native-stop-and-durable-revoke"); return nil },
		func(context.Context) error { order = append(order, "endpoint-release"); return nil },
	); err != nil {
		t.Fatal(err)
	}
	if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
		order = append(order, "commit")
		return publishNextNativeModelFixture(s)
	}); err != nil {
		t.Fatal(err)
	}
	if err := owner.cleanupRetainedNativeModels(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []string{"seal", "native-stop-and-durable-revoke", "host-revoke", "commit",
		"model-drain", "endpoint-release"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("custody order = %v, want %v", order, want)
	}
	owner.models.mu.Lock()
	remaining, quarantined := len(owner.models.leases), owner.models.quarantined
	owner.models.mu.Unlock()
	if remaining != 0 || quarantined {
		t.Fatal("completed lease remained registered after outside-lock drain")
	}
}

func TestNativeModelCustodyRegistrationRacesRotation(t *testing.T) {
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	model := &fakeNativeModelChannel{
		seal: func(ctx context.Context) error {
			once.Do(func() { close(entered) })
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		close: func(context.Context) error { return nil },
	}
	identity := nativeModelCustodyIdentity()
	model.identity, model.authority = identity, owner.current()
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	committed := make(chan struct{}, 1)
	go func() {
		done <- s.publishSandboxAuthority(ctx, func(context.Context) error {
			committed <- struct{}{}
			return publishNextNativeModelFixture(s)
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		close(release)
		t.Fatal("publication did not enter model seal")
	}
	second := identity
	second.ID = "host-model-session-two"
	second.Name = "model-session-two"
	secondModel := *model
	secondModel.identity = second
	if err := owner.retainNativeModelLease(second, owner.current(), &secondModel,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err == nil {
		close(release)
		t.Fatal("registered a new lease during authority rotation")
	}
	select {
	case <-committed:
		close(release)
		t.Fatal("publication committed before the active model writer quiesced")
	default:
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("bounded publication did not complete")
	}
	if err := owner.cleanupRetainedNativeModels(t.Context()); err != nil {
		t.Fatal(err)
	}
	secondModel.authority = owner.current()
	if err := owner.retainNativeModelLease(second, owner.current(), &secondModel,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := owner.closeNativeModelLease(t.Context(), second); err != nil {
		t.Fatal(err)
	}
}

func TestNativeModelCustodyDrainFailureRetainsAndRetries(t *testing.T) {
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	calls, endpoint := 0, 0
	sentinel := errors.New("fixed model drain refusal")
	model := &fakeNativeModelChannel{
		seal: func(context.Context) error { return nil },
		close: func(context.Context) error {
			calls++
			if calls == 1 {
				return sentinel
			}
			return nil
		},
	}
	identity := nativeModelCustodyIdentity()
	model.identity, model.authority = identity, owner.current()
	revokes := 0
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { revokes++; return nil },
		func(context.Context) error { endpoint++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
		return publishNextNativeModelFixture(s)
	}); err != nil {
		t.Fatalf("committed publication reported a drain error: %v", err)
	}
	s.drainNativeModelsAfterReload(t.Context())
	owner.models.mu.Lock()
	drainErr := owner.models.lastCleanup
	owner.models.mu.Unlock()
	if !errors.Is(drainErr, sentinel) {
		t.Fatalf("expected privately retained drain refusal, got %v", drainErr)
	}
	owner.models.mu.Lock()
	remaining, quarantined := len(owner.models.leases), owner.models.quarantined
	owner.models.mu.Unlock()
	if remaining != 1 || !quarantined || endpoint != 0 || revokes != 1 {
		t.Fatal("incomplete model drain released a lease or repeated native revocation")
	}
	second := identity
	second.ID = "host-model-session-two"
	second.Name = "model-session-two"
	secondModel := *model
	secondModel.identity = second
	if err := owner.retainNativeModelLease(second, owner.current(), &secondModel,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("cleanup uncertainty allowed a new model lease")
	}
	if err := owner.cleanupRetainedNativeModels(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || endpoint != 1 || revokes != 1 {
		t.Fatal("retry did not complete exactly the retained cleanup phases")
	}
	secondModel.authority = owner.current()
	if err := owner.retainNativeModelLease(second, owner.current(), &secondModel,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := owner.closeNativeModelLease(t.Context(), second); err != nil {
		t.Fatal(err)
	}
}

func TestNativeModelCustodyTimeoutClosesPublication(t *testing.T) {
	s := sandboxPublicationFixture(t)
	hostRevokes := 0
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { hostRevokes++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("fixed quiesce timeout")
	sealed := 0
	model := &fakeNativeModelChannel{
		seal:  func(context.Context) error { sealed++; return sentinel },
		close: func(context.Context) error { return nil },
	}
	identity := nativeModelCustodyIdentity()
	model.identity, model.authority = identity, owner.current()
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	commits := 0
	if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
		commits++
		return publishNextNativeModelFixture(s)
	}); !errors.Is(err, sentinel) {
		t.Fatalf("expected sealed quiesce error, got %v", err)
	}
	if sealed == 0 || hostRevokes != 1 || commits != 0 {
		t.Fatal("failed quiesce skipped revocation or published authority")
	}
	if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
		commits++
		return nil
	}); err == nil || commits != 0 {
		t.Fatal("failed transition admitted a later publication")
	}
	owner.models.mu.Lock()
	failed, retained := owner.models.failed, len(owner.models.leases)
	owner.models.mu.Unlock()
	if !failed || retained != 1 {
		t.Fatal("failed publication released or reopened the model owner")
	}
}

func TestNativeModelCustodyRejectsForgedTerminalIdentity(t *testing.T) {
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	order := []string{}
	model := &fakeNativeModelChannel{
		seal:  func(context.Context) error { order = append(order, "seal"); return nil },
		close: func(context.Context) error { order = append(order, "model"); return nil },
	}
	identity := nativeModelCustodyIdentity()
	model.identity, model.authority = identity, owner.current()
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { order = append(order, "native"); return nil },
		func(context.Context) error { order = append(order, "endpoint"); return nil }); err != nil {
		t.Fatal(err)
	}
	forged := identity
	forged.Owner = "other-host"
	if err := owner.closeNativeModelLease(t.Context(), forged); err == nil || len(order) != 0 {
		t.Fatal("forged owner selected or closed a retained lease")
	}
	if err := owner.closeNativeModelLease(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"seal", "native", "model", "endpoint"}) {
		t.Fatalf("terminal cleanup order = %v", order)
	}
}

func TestNativeModelCustodyReloadDrainsAfterConfigUnlock(t *testing.T) {
	for _, route := range []string{"direct", "assets", "watcher"} {
		t.Run(route, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			writeConfigForManagerTest(t, path, dir, "observe")
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			s := sandboxPublicationFixture(t)
			owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			var mgr *ConfigManager
			closed := false
			model := &fakeNativeModelChannel{
				seal: func(context.Context) error { return nil },
				close: func(context.Context) error {
					if !mgr.mu.TryLock() {
						return errors.New("model drain ran under ConfigManager lock")
					}
					mgr.mu.Unlock()
					closed = true
					return nil
				},
			}
			model.identity, model.authority = nativeModelCustodyIdentity(), owner.current()
			if err := owner.retainNativeModelLease(nativeModelCustodyIdentity(), owner.current(), model,
				func(context.Context) error { return nil },
				func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			mgr = newConfigManagerWithSnapshot(path, initial, nil, nil, "",
				func(ctx context.Context, _, _ *config.Config, _ ConfigDiff, _ configReloadSource) error {
					return s.publishSandboxAuthority(ctx, func(context.Context) error {
						return publishNextNativeModelFixture(s)
					})
				})
			mgr.afterReload = s.drainNativeModelsAfterReload
			s.configMgr = mgr
			writeConfigForManagerTest(t, path, dir, "action")
			switch route {
			case "direct":
				err = mgr.Reload(t.Context(), "direct")
			case "assets":
				err = mgr.ReloadAssets(t.Context(), "assets")
			default:
				err = mgr.reload(t.Context(), "watcher", false)
			}
			if err != nil || !closed {
				t.Fatalf("reload did not drain outside its mutex: err=%v closed=%t", err, closed)
			}
			owner.models.mu.Lock()
			pending := owner.models.rotating || len(owner.models.leases) != 0 || owner.models.lastCleanup != nil
			owner.models.mu.Unlock()
			if pending {
				t.Fatal("completed reload retained a model lease")
			}
		})
	}
}

func TestNativeModelCustodyPostcommitDrainFailureNeverRejectsGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("fixed model drain refusal")
	drains := 0
	model := &fakeNativeModelChannel{
		seal: func(context.Context) error { return nil },
		close: func(context.Context) error {
			drains++
			if drains == 1 {
				return sentinel
			}
			return nil
		},
	}
	model.identity, model.authority = nativeModelCustodyIdentity(), owner.current()
	if err := owner.retainNativeModelLease(nativeModelCustodyIdentity(), owner.current(), model,
		func(context.Context) error { return nil },
		func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "",
		func(ctx context.Context, _, _ *config.Config, _ ConfigDiff, _ configReloadSource) error {
			return s.publishSandboxAuthority(ctx, func(context.Context) error {
				return publishNextNativeModelFixture(s)
			})
		})
	mgr.afterReload = s.drainNativeModelsAfterReload
	s.configMgr = mgr
	writeConfigForManagerTest(t, path, dir, "action")
	if err := mgr.Reload(t.Context(), "first"); err != nil {
		t.Fatalf("committed generation was reported rejected: %v", err)
	}
	if mgr.Current().Guardrail.Mode != "action" {
		t.Fatal("committed generation was not published")
	}
	owner.models.mu.Lock()
	firstErr, retained := owner.models.lastCleanup, len(owner.models.leases)
	owner.models.mu.Unlock()
	if !errors.Is(firstErr, sentinel) || retained != 1 {
		t.Fatal("failed postcommit drain was not retained")
	}
	if err := mgr.Reload(t.Context(), "retry_without_diff"); err != nil {
		t.Fatal(err)
	}
	owner.models.mu.Lock()
	lastErr, remaining, rotating := owner.models.lastCleanup, len(owner.models.leases), owner.models.rotating
	owner.models.mu.Unlock()
	if drains != 2 || lastErr != nil || remaining != 0 || rotating {
		t.Fatal("no-diff reload did not retry and finish retained drain")
	}
}

func TestNativeModelCustodyRejectsMismatchedChannelBinding(t *testing.T) {
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	identity := nativeModelCustodyIdentity()
	model := &fakeNativeModelChannel{
		identity: identity, authority: owner.current(),
		seal:  func(context.Context) error { return nil },
		close: func(context.Context) error { return nil },
	}
	wrongSession := identity
	wrongSession.ID = "different-model-session"
	wrongSession.Name = "different-model-name"
	if err := owner.retainNativeModelLease(wrongSession, owner.current(), model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("registered a model adapter under another session identity")
	}
	wrongEpoch := *model
	wrongEpoch.authority.Generation++
	if err := owner.retainNativeModelLease(identity, owner.current(), &wrongEpoch,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("registered a model adapter under another publication epoch")
	}
	owner.models.mu.Lock()
	owner.models.publishing = 1
	owner.models.mu.Unlock()
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("queued publication admitted a new model lease")
	}
	owner.models.mu.Lock()
	owner.models.publishing = 0
	owner.models.mu.Unlock()
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := owner.closeNativeModelLease(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
}

func TestNativeModelCustodyBeginRefusalClosesRegistration(t *testing.T) {
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	owner.models.mu.Lock()
	owner.models.rotating = true
	owner.models.mu.Unlock()
	commits := 0
	if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
		commits++
		return publishNextNativeModelFixture(s)
	}); err == nil || commits != 0 {
		t.Fatal("overlapping authority transition did not close admission")
	}
	owner.models.mu.Lock()
	owner.models.rotating = false
	failed := owner.models.failed
	owner.models.mu.Unlock()
	if !failed {
		t.Fatal("begin refusal reopened model registration after LaunchGate closed")
	}
	identity := nativeModelCustodyIdentity()
	model := &fakeNativeModelChannel{
		identity: identity, authority: owner.current(),
		seal:  func(context.Context) error { return nil },
		close: func(context.Context) error { return nil },
	}
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("closed LaunchGate left model registration open")
	}
}

func TestNativeModelCustodyConcurrentReloadDuringTerminalDrain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var mgr *ConfigManager
	model := &fakeNativeModelChannel{
		seal: func(context.Context) error { return nil },
		close: func(ctx context.Context) error {
			if !mgr.mu.TryLock() {
				return errors.New("model drain held ConfigManager mutex")
			}
			mgr.mu.Unlock()
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	identity := nativeModelCustodyIdentity()
	model.identity, model.authority = identity, owner.current()
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	generation := uint64(987654)
	mgr = newConfigManagerWithSnapshot(path, initial, nil, nil, "",
		func(ctx context.Context, _, _ *config.Config, _ ConfigDiff, _ configReloadSource) error {
			next := generation
			generation++
			return s.publishSandboxAuthority(ctx, func(context.Context) error {
				return publishNativeModelFixtureGeneration(s, next)
			})
		})
	mgr.afterReload = s.drainNativeModelsAfterReload
	s.configMgr = mgr
	writeConfigForManagerTest(t, path, dir, "action")
	first := make(chan error, 1)
	go func() { first <- mgr.Reload(ctx, "first") }()
	select {
	case <-entered:
	case <-ctx.Done():
		close(release)
		t.Fatal("first reload did not enter postcommit model drain")
	}
	writeConfigForManagerTest(t, path, dir, "observe")
	second := make(chan error, 1)
	go func() { second <- mgr.Reload(ctx, "second") }()
	select {
	case err := <-second:
		if err != nil {
			close(release)
			t.Fatal(err)
		}
	case <-ctx.Done():
		close(release)
		t.Fatal("second publication waited for the first model drain")
	}
	if generation != 987656 {
		close(release)
		t.Fatalf("expected two advancing publications, next generation = %d", generation)
	}
	owner.models.mu.Lock()
	quarantined := owner.models.quarantined
	owner.models.mu.Unlock()
	if !quarantined {
		close(release)
		t.Fatal("second publication reopened registration before old drain")
	}
	close(release)
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("first drain did not finish")
	}
	owner.models.mu.Lock()
	remaining, pending := len(owner.models.leases), owner.models.quarantined || owner.models.rotating
	owner.models.mu.Unlock()
	if remaining != 0 || pending {
		t.Fatal("finished reload retained a model lease or quarantine")
	}
}

func TestNativeModelCustodyReentrantReloadDuringDrain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var mgr *ConfigManager
	nested := 0
	model := &fakeNativeModelChannel{
		seal: func(context.Context) error { return nil },
		close: func(context.Context) error {
			if !mgr.mu.TryLock() {
				return errors.New("model drain held ConfigManager mutex")
			}
			mgr.mu.Unlock()
			nested++
			writeConfigForManagerTest(t, path, dir, "observe")
			return mgr.Reload(ctx, "reentrant")
		},
	}
	identity := nativeModelCustodyIdentity()
	model.identity, model.authority = identity, owner.current()
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	generation := uint64(987654)
	mgr = newConfigManagerWithSnapshot(path, initial, nil, nil, "",
		func(ctx context.Context, _, _ *config.Config, _ ConfigDiff, _ configReloadSource) error {
			next := generation
			generation++
			return s.publishSandboxAuthority(ctx, func(context.Context) error {
				return publishNativeModelFixtureGeneration(s, next)
			})
		})
	mgr.afterReload = s.drainNativeModelsAfterReload
	s.configMgr = mgr
	writeConfigForManagerTest(t, path, dir, "action")
	done := make(chan error, 1)
	go func() { done <- mgr.Reload(ctx, "outer") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("model drain deadlocked on its own reentrant reload")
	}
	if nested != 1 || generation != 987656 || mgr.Current().Guardrail.Mode != "observe" {
		t.Fatal("reentrant reload did not publish the second generation")
	}
	owner.models.mu.Lock()
	remaining, pending := len(owner.models.leases), owner.models.quarantined || owner.models.rotating
	owner.models.mu.Unlock()
	if remaining != 0 || pending {
		t.Fatal("reentrant drain retained a model lease or quarantine")
	}
}

func TestNativeModelCustodyTerminalCloseFailureQuarantines(t *testing.T) {
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	identity := nativeModelCustodyIdentity()
	sentinel := errors.New("fixed terminal drain refusal")
	closes := 0
	model := &fakeNativeModelChannel{
		identity: identity, authority: owner.current(),
		seal: func(context.Context) error { return nil },
		close: func(context.Context) error {
			closes++
			if closes == 1 {
				return sentinel
			}
			return nil
		},
	}
	revokes := 0
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { revokes++; return nil },
		func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := owner.closeNativeModelLease(t.Context(), identity); !errors.Is(err, sentinel) {
		t.Fatalf("terminal cleanup error lost: %v", err)
	}
	other := identity
	other.ID = "host-model-session-two"
	other.Name = "model-session-two"
	otherModel := *model
	otherModel.identity = other
	if err := owner.retainNativeModelLease(other, owner.current(), &otherModel,
		func(context.Context) error { return nil },
		func(context.Context) error { return nil }); err == nil {
		t.Fatal("terminal cleanup uncertainty admitted a new session")
	}
	if err := owner.closeNativeModelLease(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	if closes != 2 || revokes != 1 {
		t.Fatal("terminal retry repeated native revoke or skipped retained model")
	}
	owner.models.mu.Lock()
	quarantined, remaining := owner.models.quarantined, len(owner.models.leases)
	owner.models.mu.Unlock()
	if quarantined || remaining != 0 {
		t.Fatal("successful direct terminal retry kept empty registry quarantined")
	}
	if err := owner.retainNativeModelLease(other, owner.current(), &otherModel,
		func(context.Context) error { return nil },
		func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := owner.closeNativeModelLease(t.Context(), other); err != nil {
		t.Fatal(err)
	}
}

func TestNativeModelCustodyDurableRevokeCompletionBypassesDrainSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	calls := 0
	lease := &nativeModelLease{
		op: make(chan struct{}, 1), revokedDone: make(chan struct{}),
		revokeOwned: func(context.Context) error { calls++; return nil },
	}
	// The terminal path completed durable revoke and then retained op while
	// draining the model. The publication path already passed its first
	// revoked check and must still finish before the terminal releases op.
	lease.op <- struct{}{}
	result := make(chan error, 1)
	go func() { result <- lease.revokeAfterInitialCheck(ctx) }()
	lease.revoked.Store(true)
	close(lease.revokedDone)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("publication waited for terminal model drain after durable revoke")
	}
	if calls != 0 {
		t.Fatal("publication repeated the durable native revoke")
	}
	<-lease.op
}

func TestNativeModelCustodyPublicationBypassesTerminalDrain(t *testing.T) {
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	identity := nativeModelCustodyIdentity()
	model := &fakeNativeModelChannel{
		identity: identity, authority: owner.current(),
		seal: func(context.Context) error { return nil },
		close: func(ctx context.Context) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	terminal := make(chan error, 1)
	go func() { terminal <- owner.closeNativeModelLease(ctx, identity) }()
	select {
	case <-entered:
	case <-ctx.Done():
		close(release)
		t.Fatal("terminal owner did not enter model drain")
	}
	published := make(chan error, 1)
	go func() {
		published <- s.publishSandboxAuthority(ctx, func(context.Context) error {
			return publishNextNativeModelFixture(s)
		})
	}()
	select {
	case err := <-published:
		if err != nil {
			close(release)
			t.Fatal(err)
		}
	case <-ctx.Done():
		close(release)
		t.Fatal("publication waited for terminal model drain")
	}
	close(release)
	select {
	case err := <-terminal:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("terminal owner did not complete")
	}
	if err := owner.cleanupRetainedNativeModels(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNativeModelCustodyNoDeadlinePublicationBoundsQuiesce(t *testing.T) {
	s := sandboxPublicationFixture(t)
	hostRevokes := 0
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error {
		hostRevokes++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := nativeModelCustodyIdentity()
	model := &fakeNativeModelChannel{
		identity: identity, authority: owner.current(),
		seal: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		close: func(context.Context) error { return nil },
	}
	if err := owner.retainNativeModelLease(identity, owner.current(), model,
		func(context.Context) error { return nil },
		func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	commits := 0
	result := make(chan error, 1)
	go func() {
		result <- s.publishSandboxAuthority(context.Background(), func(context.Context) error {
			commits++
			return publishNextNativeModelFixture(s)
		})
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unbounded parent lost finite cleanup deadline: %v", err)
		}
	case <-time.After(nativeModelPublicationLimit + 3*time.Second):
		t.Fatal("long-lived watcher context held publication locks indefinitely")
	}
	owner.models.mu.Lock()
	failed, quarantined, retained := owner.models.failed, owner.models.quarantined, len(owner.models.leases)
	owner.models.mu.Unlock()
	if hostRevokes != 1 || commits != 0 || !failed || !quarantined || retained != 1 {
		t.Fatal("timed-out cleanup published authority or released the retained owner")
	}
}
