// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64 && axis_native_contained_hook_canary

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/test/e2e/axis/native-hook-canary/fixture"
	"golang.org/x/sys/unix"
)

const containedPeerSHA = "sha256:e2afdf64b0456817f469eb3a7acf3eceb43bc204187a194f3c5e8d54a68c3e3c"
const containedBwrapSHA = "sha256:b4d1a59426c6a52e9f9a0d57d03d620e4dfc1beef976201a3afc0c1b492ee37d"

// This contributor-only registry retains the cleanup closure (and every exact
// resource it captures) after a failed test. It has room for the two fixed
// selectors' thirteen cases, never launches work, and owns no lifecycle API.
var containedRetained struct {
	sync.Mutex
	owners [13]*containedCleanup
	failed bool
}

type containedCleanup struct {
	mu       sync.Mutex
	close    func(context.Context) error
	err      error
	complete bool
}

func retainContainedCleanup(closeResources func(context.Context) error) *containedCleanup {
	containedRetained.Lock()
	defer containedRetained.Unlock()
	if closeResources == nil || containedRetained.failed {
		return nil
	}
	for index, current := range containedRetained.owners {
		if current == nil {
			owner := &containedCleanup{close: closeResources}
			containedRetained.owners[index] = owner
			return owner
		}
	}
	return nil
}

func (owner *containedCleanup) Close(ctx context.Context) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.complete || owner.err != nil {
		return owner.err
	}
	owner.err = owner.close(ctx)
	if owner.err != nil {
		// Sticky uncertainty: do not drop the closure, retry a questionable
		// file close or relabel a partial release as success.
		containedRetained.Lock()
		containedRetained.failed = true
		containedRetained.Unlock()
		return owner.err
	}
	owner.complete = true
	owner.close = nil
	containedRetained.Lock()
	defer containedRetained.Unlock()
	for index, current := range containedRetained.owners {
		if current == owner {
			containedRetained.owners[index] = nil
			break
		}
	}
	return nil
}

// containedAuditV8Fixture owns the actual local SQLite audit store, logger and
// generated v8 runtime. The retained canary owner registers this value before
// prepare can allocate anything, then closes it only after native/endpoint
// shutdown and binding revocation. No sink or fake audit emitter is substituted.
type containedAuditV8Fixture struct {
	store   *audit.Store
	logger  *audit.Logger
	runtime *observabilityruntime.Runtime
}

func (f *containedAuditV8Fixture) prepare(ctx context.Context, directory string) error {
	if f == nil || ctx == nil || directory == "" || f.store != nil {
		return errors.New("fixed audit fixture admission refused")
	}
	path := filepath.Join(directory, config.DefaultAuditDBName)
	var err error
	f.store, err = audit.NewStore(path)
	if err != nil {
		return err
	}
	if err := f.store.Init(); err != nil {
		return err
	}
	f.logger = audit.NewLogger(f.store)
	retentionDays := 0
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: path, JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"),
			RetentionDays: &retentionDays,
		},
	})
	if err != nil {
		return err
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		return err
	}
	var failureIDs atomic.Uint64
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("fixed-hook-failure-%d", failureIDs.Add(1)), nil
		}),
	)
	if err != nil {
		return err
	}
	reaper, err := audit.NewRetentionReaper(f.store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		return err
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{},
	)
	if err != nil {
		return err
	}
	f.runtime, err = observabilityruntime.New(
		ctx, runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: f.store, Engine: engine, RecordBuilder: builder,
			Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
			TelemetryProviderFactory: telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
				Version: "8.0.0", Environment: "test",
				ServiceInstanceID: "fixed-contained-hook", DefenseClawInstanceID: "fixed-contained-hook",
			}),
		},
	)
	if err != nil {
		return err
	}
	f.logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{
		runtime: f.runtime, redactionEngine: engine,
	})
	return nil
}

func (f *containedAuditV8Fixture) rows(connector, allowEvent, blockEvent string) error {
	if f == nil || f.store == nil || connector == "" || allowEvent == "" || blockEvent == "" {
		return errors.New("fixed audit store or event unavailable")
	}
	events, err := f.store.ListEvents(64)
	if err != nil {
		return err
	}
	if len(events) >= 64 {
		return errors.New("fixed audit inventory exceeds complete bound")
	}
	allow, block := 0, 0
	for _, event := range events {
		if event.Action != string(audit.ActionConnectorHook) {
			continue
		}
		if event.Connector != connector {
			return errors.New("fixed connector audit identity differs")
		}
		if event.Enforced {
			if event.Target != blockEvent {
				return errors.New("fixed blocked audit event differs")
			}
			block++
		} else {
			if event.Target != allowEvent {
				return errors.New("fixed allowed audit event differs")
			}
			allow++
		}
	}
	if allow != 1 || block != 1 {
		return fmt.Errorf("fixed durable connector audit rows allow=%d block=%d, want one each", allow, block)
	}
	return nil
}

func (f *containedAuditV8Fixture) close(ctx context.Context) error {
	if f == nil {
		return nil
	}
	if f.runtime != nil {
		if err := f.runtime.Close(ctx); err != nil {
			return err
		}
		f.runtime = nil
	}
	if f.logger != nil {
		f.logger.Close()
		f.logger = nil
	}
	if f.store != nil {
		if err := f.store.Close(); err != nil {
			return err
		}
		f.store = nil
	}
	return nil
}

func TestFixedContainedHookCleanupRetainsUncertainOwnerWithoutNative(t *testing.T) {
	// assets.prepare cancels its factory context at successful return. A
	// child of the retained lifetime must outlive that operation context.
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	assets, spec := nativeHookAssetFake(t)
	assets.lifetime = lifetime
	var scoped, retainedSession context.Context
	closed := false
	preparedProcess := &nativeHookAssetFakeProcess{
		close: func(context.Context) error { closed = true; return nil },
		launch: func(context.Context, sandboxruntime.Spec) (sandboxruntime.Instance, error) {
			return sandboxruntime.Instance{Identity: spec.Identity, Phase: "started"}, nil
		},
	}
	if _, err := assets.prepare(lifetime, spec, []string{bridgeproto.HookDirectory},
		func(ctx context.Context, _ *os.File, _ *bridgeproto.Hook) (sandboxruntime.PreparedProcess, error) {
			scoped = ctx
			owned, cancelOwned, stopPrepare, err := containedSessionLifetime(ctx, lifetime)
			if err != nil {
				return preparedProcess, err
			}
			defer stopPrepare()
			retainedSession = owned
			preparedProcess.close = func(context.Context) error {
				cancelOwned()
				closed = true
				return nil
			}
			return preparedProcess, nil
		}); err != nil {
		t.Fatal("fake preparation refused owned lifetime")
	}
	if scoped == nil || scoped.Err() != context.Canceled || retainedSession == scoped || retainedSession.Err() != nil {
		t.Fatal("peer owner inherited canceled preparation context")
	}
	if _, err := assets.Launch(lifetime, spec); err != nil {
		t.Fatal("prepared fake could not launch after prepare returned")
	}
	if err := assets.Close(context.Background()); err != nil || !closed || retainedSession.Err() != context.Canceled {
		t.Fatal("fake native cleanup did not cancel retained session lifetime")
	}

	partialLifetime, cancelPartialLifetime := context.WithCancel(context.Background())
	defer cancelPartialLifetime()
	partialAssets, partialSpec := nativeHookAssetFake(t)
	partialAssets.lifetime = partialLifetime
	operation, cancelOperation := context.WithCancel(partialLifetime)
	defer cancelOperation()
	partialClosed := false
	partialProcess := &nativeHookAssetFakeProcess{close: func(context.Context) error { partialClosed = true; return nil }}
	if owner, err := partialAssets.prepare(operation, partialSpec, []string{bridgeproto.HookDirectory},
		func(ctx context.Context, _ *os.File, _ *bridgeproto.Hook) (sandboxruntime.PreparedProcess, error) {
			owned, cancelOwned, stopPrepare, setupErr := containedSessionLifetime(ctx, partialLifetime)
			if setupErr != nil {
				return partialProcess, setupErr
			}
			defer stopPrepare()
			partialProcess.close = func(context.Context) error {
				cancelOwned()
				partialClosed = true
				return nil
			}
			cancelOperation()
			select {
			case <-owned.Done():
			case <-time.After(time.Second):
				t.Fatal("canceled preparation did not stop retained native start")
			}
			return partialProcess, ctx.Err()
		}); owner != partialAssets || !errors.Is(err, context.Canceled) || partialAssets.complete {
		t.Fatal("canceled preparation escaped with a launchable process")
	}
	if err := partialAssets.Close(context.Background()); err != nil || !partialClosed {
		t.Fatal("partial native process was not retained for cleanup")
	}

	// These facts are all that a failed actual launch may publish. The
	// underlying error text and any uncorrelated failure payload stay private.
	binding := bridgeproto.Binding{SessionID: "fixed"}
	failed := bridgeproto.Frame{Kind: bridgeproto.Failed, Request: 7, Binding: binding,
		Failure: &bridgeproto.Failure{Code: "launch_failed"}}
	if got := containedLaunchFrameObservation(failed, 7, binding); got.Step != "failed_frame" ||
		got.FrameKind != "failed" || got.FailureCode != "launch_failed" || got.NativeStage != "" {
		t.Fatal("correlated closed failure was lost")
	}
	failed.Request = 8
	if got := containedLaunchFrameObservation(failed, 7, binding); got.Step != "correlation" || got.FailureCode != "" {
		t.Fatal("uncorrelated peer data escaped")
	}
	failed.Request = 7
	failed.Failure.Code = "private:/host/path"
	if got := containedLaunchFrameObservation(failed, 7, binding); got.FailureCode != "" {
		t.Fatal("unclosed peer code escaped")
	}
	stage := bridgeproto.NativePreparationStage("windows_cwd_privacy")
	failed.Failure = &bridgeproto.Failure{Code: "preparation_failed", NativeStage: &stage}
	if got := containedLaunchFrameObservation(failed, 7, binding); got.FailureCode != "preparation_failed" ||
		got.NativeStage != string(stage) {
		t.Fatal("closed native stage was lost")
	}
	if got := containedKnownError(errors.Join(bridgeowner.ErrPeer, containedPrivateError{})); got != "peer" {
		t.Fatal("private error text was consulted or exposed")
	}
	// The ordinary local v8 runtime must commit both connector verdicts to
	// SQLite before the same retained owner releases its store. No native
	// process, socket listener, or guest mount participates in this test.
	auditFixture := &containedAuditV8Fixture{}
	auditOwner := retainContainedCleanup(func(ctx context.Context) error {
		return auditFixture.close(ctx)
	})
	if auditOwner == nil {
		t.Fatal("fixed audit fixture owner unavailable")
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := auditOwner.Close(closeCtx); err != nil {
			t.Error("fixed audit fixture cleanup incomplete")
		}
	}()
	auditDirectory, err := os.MkdirTemp("", "fixed-hook-audit-")
	if err != nil {
		t.Fatal("fixed audit directory unavailable")
	}
	if err := auditFixture.prepare(context.Background(), auditDirectory); err != nil {
		t.Fatal("fixed audit v8 runtime unavailable")
	}
	auditAPI := &APIServer{logger: auditFixture.logger}
	for _, action := range []string{"allow", "block"} {
		if err := auditAPI.logConnectorHookAuditEnvelope(context.Background(), HookAuditEnvelope{
			Connector: "claudecode", Event: "PreToolUse",
			Action: action, RawAction: action, Mode: "action", Enforced: action == "block",
		}); err != nil {
			t.Fatal("fixed generated v8 connector audit write refused")
		}
	}
	if err := auditFixture.rows("claudecode", "PreToolUse", "PreToolUse"); err != nil {
		t.Fatal("fixed generated v8 connector rows not durable")
	}
	failure := errors.New("fixed fake close uncertainty")
	calls := 0
	held := &struct{ value string }{"fixed retained resource"}
	owner := retainContainedCleanup(func(context.Context) error {
		calls++
		if held.value != "fixed retained resource" {
			t.Fatal("retained resource changed")
		}
		return failure
	})
	if owner == nil {
		t.Fatal("fake cleanup owner unavailable")
	}
	complete := retainContainedCleanup(func(context.Context) error { return nil })
	if complete == nil {
		t.Fatal("fake successful cleanup owner unavailable")
	}
	first, second := owner.Close(context.Background()), owner.Close(context.Background())
	if !errors.Is(first, failure) || !errors.Is(second, failure) || calls != 1 || owner.close == nil || owner.complete {
		t.Fatal("uncertain owner was retried, lost or marked complete")
	}
	containedRetained.Lock()
	retained := false
	for _, current := range containedRetained.owners {
		retained = retained || current == owner
	}
	containedRetained.Unlock()
	if !retained {
		t.Fatal("uncertain cleanup closure lost its root reference")
	}
	if retainContainedCleanup(func(context.Context) error { return nil }) != nil {
		t.Fatal("new case admitted after cleanup uncertainty")
	}
	if complete.Close(context.Background()) != nil || !complete.complete || complete.close != nil {
		t.Fatal("successful cleanup did not relinquish its closure")
	}
	// The intentionally retained fake closure owns no native resource or file.
}

type containedPrivateError struct{}

func (containedPrivateError) Error() string { panic("private error text was formatted") }

// Only closed labels enter the public contributor result. Error() and raw
// protocol strings are never consulted, even for an unexpected peer failure.
type containedLaunchObservation struct {
	Step        string `json:"step"`
	FrameKind   string `json:"frame_kind,omitempty"`
	FailureCode string `json:"failure_code,omitempty"`
	NativeStage string `json:"native_stage,omitempty"`
	OwnerError  string `json:"owner_error,omitempty"`
}

type containedCleanupObservation struct {
	Step       string `json:"step"`
	OwnerError string `json:"owner_error,omitempty"`
}

func containedKnownError(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, bridgeowner.ErrCleanup):
		return "owner_cleanup"
	case errors.Is(err, bridgeowner.ErrPeer):
		return "peer"
	case errors.Is(err, bridgeowner.ErrBackpressure):
		return "backpressure"
	case errors.Is(err, bridgeowner.ErrClosed):
		return "owner_closed"
	case errors.Is(err, bridgeproto.ErrProtocol):
		return "protocol"
	case errors.Is(err, bridgeprocess.ErrAdmission):
		return "native_admission"
	case errors.Is(err, bridgeprocess.ErrUnavailable):
		return "native_unavailable"
	case errors.Is(err, errNativeHookAssets):
		return "assets"
	case errors.Is(err, io.EOF):
		return "eof"
	default:
		return "other"
	}
}

func containedClosedFrameKind(kind bridgeproto.Kind) string {
	switch kind {
	case bridgeproto.Prepare, bridgeproto.Launch, bridgeproto.Input, bridgeproto.InputEOF,
		bridgeproto.Resize, bridgeproto.Cancel, bridgeproto.Wait, bridgeproto.Destroy,
		bridgeproto.Prepared, bridgeproto.Started, bridgeproto.Output, bridgeproto.Exited,
		bridgeproto.Destroyed, bridgeproto.Failed:
		return string(kind)
	default:
		return "other"
	}
}

func containedClosedFailureCode(code string) string {
	switch code {
	case "invalid_request", "unsupported", "preparation_failed", "launch_failed", "io_failed", "cleanup_failed":
		return code
	default:
		return ""
	}
}

func containedLaunchFrameObservation(frame bridgeproto.Frame, request uint64, binding bridgeproto.Binding) containedLaunchObservation {
	if frame.Request != request || frame.Binding != binding {
		return containedLaunchObservation{Step: "correlation"}
	}
	if frame.Kind == bridgeproto.Started {
		return containedLaunchObservation{}
	}
	observation := containedLaunchObservation{Step: "unexpected_frame", FrameKind: containedClosedFrameKind(frame.Kind)}
	if frame.Kind != bridgeproto.Failed || frame.Failure == nil {
		return observation
	}
	observation.Step = "failed_frame"
	observation.FailureCode = containedClosedFailureCode(frame.Failure.Code)
	if observation.FailureCode == "preparation_failed" && frame.Failure.NativeStage != nil &&
		bridgeproto.ValidNativePreparationStage(string(*frame.Failure.NativeStage)) {
		observation.NativeStage = string(*frame.Failure.NativeStage)
	}
	return observation
}

// This host-only test checks the schema/evaluator oracle before any native
// attempt. Its in-process transport is explicitly not containment evidence.
type containedFixtureTransport struct {
	handler http.Handler
	token   string
}

func (transport containedFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	forward := request.Clone(request.Context())
	forward.Header = request.Header.Clone()
	forward.Header.Set("Authorization", "Bearer "+transport.token)
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, forward)
	return recorder.Result(), nil
}

func TestFixedContainedHookSharedEvaluatorOracleWithoutNative(t *testing.T) {
	names := sharedDefaultRegistry().Names()
	// OpenClaw and ZeptoClaw are built-ins, but this fixed canary covers the
	// twelve agent-hook connectors. Refuse any other registry addition.
	if len(names) != len(fixture.Cases())+2 {
		t.Fatal("fixed payload inventory differs from actual connector registry")
	}
	extra := map[string]bool{"openclaw": false, "zeptoclaw": false}
	for _, name := range names {
		if _, ok := extra[name]; ok {
			extra[name] = true
			continue
		}
		if _, err := fixture.Lookup(name); err != nil {
			t.Fatal("actual connector absent from fixed payload inventory")
		}
	}
	if !extra["openclaw"] || !extra["zeptoclaw"] {
		t.Fatal("fixed non-canary built-in inventory differs")
	}
	for _, value := range fixture.Cases() {
		t.Run(value.Name, func(t *testing.T) {
			decisions := make(chan SandboxHookDecision, 8)
			api := newSandboxIngressFixture(t, func(config *SandboxIngressConfig) {
				config.OnHookDecision = func(value SandboxHookDecision) { decisions <- value }
			})
			api.api.scannerCfg.Guardrail.Mode = "action"
			api.api.scannerCfg.Guardrail.Connector = value.Name
			resolution := connector.ResolveSandboxHookContract(value.Name, value.Version)
			if resolution.Status != connector.HookCompatibilityKnown {
				t.Fatal("fixture schema version no longer known")
			}
			binding, token, err := api.store.Mint(sandboxauth.Spec{SandboxID: "fixture-" + value.Name, SandboxName: "fixture-" + value.Name, Connector: value.Name, AgentVersion: value.Version, HookContractID: resolution.Contract.ContractID, ExecutionOS: "linux", PolicyProfile: "open", Routes: []sandboxauth.Route{sandboxauth.RouteHook}, Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}, TTL: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := api.store.Revoke(binding.ID); err != nil && !errors.Is(err, sandboxauth.ErrNotFound) {
					t.Error("host-only oracle binding revoke failed")
				}
			}()
			profile := &hookexec.NativeSandboxProfile{Version: 1, SessionID: binding.SandboxID, Connector: value.Name, HookContract: resolution.Contract.ContractID}
			for _, phase := range []byte{'A', 'B'} {
				raw, _ := value.Payload(phase)
				var stdout, stderr bytes.Buffer
				code := hookexec.Run(context.Background(), hookexec.Options{Connector: value.Name, Event: value.Event, HookContractID: profile.HookContract, NativeSandbox: profile, Stdin: bytes.NewReader(raw), Stdout: &stdout, Stderr: &stderr, HTTPClient: &http.Client{Transport: containedFixtureTransport{api.handler, token}}})
				want := "allow"
				if phase == 'B' {
					want = "block"
				}
				select {
				case decision := <-decisions:
					if decision.BindingID != binding.ID || decision.SandboxName != binding.SandboxName || decision.Connector != value.Name || decision.Action != want || decision.WouldBlock {
						t.Fatal("actual evaluator schema oracle differs")
					}
				default:
					t.Fatal("request did not reach actual shared evaluator")
				}
				if value.Name == "claudecode" && fixture.ValidateClaudeRow(phase, fixture.Row{Phase: string(phase), Code: code, Stdout: stdout.String(), Stderr: stderr.String()}) != nil {
					t.Fatal("existing Claude hook response differs")
				}
			}
			if value.Name == "claudecode" {
				// Exercise the actual closed-admission handler without a listener,
				// child or evaluator call. The matching private context marker is
				// normally installed by this endpoint's accepted connection.
				sealed := &nativeSandboxHookIngress{closing: true}
				handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					sealed.ServeHTTP(w, request.WithContext(context.WithValue(request.Context(), nativeHookConnectionKey{}, sealed)))
				})
				raw, _ := value.Payload('L')
				var stdout, stderr bytes.Buffer
				code := hookexec.Run(context.Background(), hookexec.Options{Connector: value.Name, Event: value.Event, HookContractID: profile.HookContract, NativeSandbox: profile, Stdin: bytes.NewReader(raw), Stdout: &stdout, Stderr: &stderr, HTTPClient: &http.Client{Transport: containedFixtureTransport{handler, token}}})
				if fixture.ValidateClaudeRow('L', fixture.Row{Phase: "L", Code: code, Stdout: stdout.String(), Stderr: stderr.String()}) != nil {
					t.Fatal("closed admission differs from existing Claude strict-client response")
				}
				select {
				case <-decisions:
					t.Fatal("host-only closed admission produced a policy decision")
				default:
				}
			}
		})
	}
}

type containedHookProcess struct {
	identity           sandboxruntime.SessionIdentity
	binding            bridgeproto.Binding
	session            *bridgeprocess.Session
	grant              *os.File
	cancelSession      context.CancelFunc
	launchRequest      uint64
	launched, complete bool
	output             []byte
	outputBytes        int
	launchObservation  containedLaunchObservation
	cleanupObservation containedCleanupObservation
}

func (process *containedHookProcess) Close(ctx context.Context) error {
	if process.complete {
		return nil
	}
	if process.session != nil {
		if err := process.session.Close(ctx); err != nil {
			process.cleanupObservation = containedCleanupObservation{Step: "session_close", OwnerError: containedKnownError(err)}
			return err
		}
		if err := process.session.StopAndWait(ctx); err != nil {
			process.cleanupObservation = containedCleanupObservation{Step: "native_stop_wait", OwnerError: containedKnownError(err)}
			return err
		}
	}
	// Cancel only after exact native cleanup. Canceling before Protocol.Close
	// would itself turn an otherwise successful owner close into canceled.
	if process.cancelSession != nil {
		process.cancelSession()
	}
	if ctx.Err() != nil {
		process.cleanupObservation = containedCleanupObservation{Step: "cleanup_context", OwnerError: containedKnownError(ctx.Err())}
		return ctx.Err()
	}
	if process.grant != nil {
		if err := process.grant.Close(); err != nil {
			process.cleanupObservation = containedCleanupObservation{Step: "grant_close", OwnerError: containedKnownError(err)}
			return err
		}
		process.grant = nil
	}
	process.complete = true
	return nil
}

func (process *containedHookProcess) Launch(ctx context.Context, spec sandboxruntime.Spec) (sandboxruntime.Instance, error) {
	if process.launched || process.complete || process.session == nil || process.session.Protocol == nil || sandboxruntime.ValidateOwnedSession(process.identity, spec.Identity) != nil {
		return sandboxruntime.Instance{}, errors.New("fixed native launch is unavailable")
	}
	process.launched = true
	process.launchObservation = containedLaunchObservation{Step: "send"}
	request, err := process.session.Protocol.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Launch})
	if err != nil {
		process.launchObservation.OwnerError = containedKnownError(err)
		return sandboxruntime.Instance{}, err
	}
	process.launchRequest = request
	process.launchObservation.Step = "receive"
	frame, err := process.session.Protocol.Receive(ctx)
	if err != nil {
		process.launchObservation.OwnerError = containedKnownError(err)
		return sandboxruntime.Instance{}, errors.New("fixed native Started correlation differs")
	}
	process.launchObservation = containedLaunchFrameObservation(frame, request, process.binding)
	if process.launchObservation.Step != "" {
		return sandboxruntime.Instance{}, errors.New("fixed native Started correlation differs")
	}
	return sandboxruntime.Instance{Identity: process.identity, Phase: "started", Workdir: "/work"}, nil
}

func (process *containedHookProcess) row(ctx context.Context) (fixture.Row, error) {
	for {
		if end := bytes.IndexByte(process.output, '\n'); end >= 0 {
			raw := process.output[:end]
			process.output = process.output[end+1:]
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			var row fixture.Row
			var extra any
			if decoder.Decode(&row) != nil || decoder.Decode(&extra) != io.EOF {
				return row, errors.New("fixed payload row differs")
			}
			return row, nil
		}
		frame, err := process.session.Protocol.Receive(ctx)
		if err != nil || frame.Kind != bridgeproto.Output || frame.Request != process.launchRequest || frame.Binding != process.binding || frame.Data == nil || frame.Data.Stream != "stdout" {
			return fixture.Row{}, errors.New("fixed payload output correlation differs")
		}
		process.outputBytes += len(frame.Data.Bytes)
		if process.outputBytes > 128<<10 || len(process.output)+len(frame.Data.Bytes) > 64<<10 {
			return fixture.Row{}, errors.New("fixed payload output bound exceeded")
		}
		process.output = append(process.output, frame.Data.Bytes...)
	}
}

func containedDigest(value any) string {
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func containedImage(ctx context.Context, root *os.File, leaf, digest string, held *[]*os.File) (*bridgeprocess.Image, error) {
	fd, err := unix.Openat(int(root.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "fixed-admitted-input")
	*held = append(*held, file) // retain the raw input even if sealing fails
	return bridgeprocess.SealImage(ctx, file, digest)
}

// The native peer must keep an execution lifetime after assets.prepare cancels
// its scoped factory context. During preparation, cancellation still stops a
// pending Start; after successful preparation the watcher is detached before
// assets.prepare's deferred cancel. The returned cancel belongs to the
// retained process and is canceled only after exact native cleanup succeeds.
func containedSessionLifetime(preparing, lifetime context.Context) (context.Context, context.CancelFunc, func() bool, error) {
	if preparing == nil || lifetime == nil || preparing.Err() != nil || lifetime.Err() != nil {
		return nil, nil, nil, errors.New("fixed native owner lifetime unavailable")
	}
	owned, cancel := context.WithCancel(lifetime)
	stop := context.AfterFunc(preparing, cancel)
	if err := preparing.Err(); err != nil {
		stop()
		cancel()
		return nil, nil, nil, err
	}
	return owned, cancel, stop, nil
}

// This is an opt-in finite contributor test, never a provider qualification.
// The two selectors are fixed in source. ROOT sequences the single Claude
// attempt before the separate all-twelve exchange matrix; neither runs in the
// ordinary host suite or during compile-only validation.
func TestContainedNativeHookClaudeUsesActualSharedEvaluator(t *testing.T) {
	value, _ := fixture.Lookup("claudecode")
	runContainedHookCase(t, value)
}
func TestContainedNativeHookAllTwelveUseActualSharedEvaluator(t *testing.T) {
	for _, value := range fixture.Cases() {
		if !t.Run(value.Name, func(t *testing.T) { runContainedHookCase(t, value) }) {
			// No next session while a failed case may retain native custody.
			return
		}
	}
}
func runContainedHookCase(t *testing.T, value fixture.Case) {
	if len(containedPayloadSHA) != 71 || !strings.HasPrefix(containedPayloadSHA, "sha256:") {
		t.Fatal("contained hook payload admission is closed before filesystem/native operations")
	}
	record := map[string]any{"scope": "fixed synthetic contained hook exchange", "connector": value.Name, "declared_schema_version": value.Version, "actual_synthetic_payload": containedPayloadSHA,
		"prepared": false, "started": false, "exited": false, "destroyed": false, "native_and_endpoint_cleanup": false, "binding_mint_attempted": false, "binding_issued": false, "binding_revoked": false, "vendor_runtime_qualification": false, "production_qualification": false, "native_surface": value.NativeSurface}
	var rows []fixture.Row
	var observed []SandboxHookDecision
	var process *containedHookProcess
	defer func() {
		if process != nil && process.launchObservation.Step != "" {
			record["native_launch_observation"] = process.launchObservation
		}
		if process != nil && process.cleanupObservation.Step != "" {
			record["native_cleanup_observation"] = process.cleanupObservation
		}
		record["rows"] = rows
		record["decisions"] = observed
		raw, err := json.Marshal(record)
		if err != nil || len(raw) > 256<<10 {
			t.Error("fixed result exceeds evidence bound")
			return
		}
		t.Logf("CONTAINED_HOOK_RESULT %s", raw)
	}()
	if os.Geteuid() <= 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		t.Fatal("fixed native host identity floor refused")
	}
	lifetime, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var inputs, parent *os.File
	var peer, bwrap, payload *bridgeprocess.Image
	var sourceFiles, workspace, hostDirs []*os.File
	var assets *nativeSandboxHookAssets
	var api *APIServer
	var store *sandboxauth.FileStore
	var auditFixture containedAuditV8Fixture
	var binding sandboxauth.Binding
	var token string
	mintAttempted := false
	// Register before the FIRST fallible input open/seal. The retained closure
	// captures these variables as each allocation publishes ownership. A nil
	// producer means no native operation has yet been attempted.
	owner := retainContainedCleanup(func(cleanup context.Context) error {
		if assets != nil {
			if err := assets.Close(cleanup); err != nil {
				if process == nil || process.cleanupObservation.Step == "" {
					record["native_cleanup_observation"] = containedCleanupObservation{Step: "assets_close", OwnerError: containedKnownError(err)}
				}
				return err
			}
			if process != nil && !process.complete {
				record["native_cleanup_observation"] = containedCleanupObservation{Step: "process_incomplete"}
				return errors.New("fixed native cleanup observation incomplete")
			}
			if process != nil {
				record["native_and_endpoint_cleanup"] = true
			}
		} else if process != nil {
			return errors.New("fixed native cleanup owner absent")
		}
		// The producer's successful Close already durably revoked its exact
		// binding after native stop. Before producer construction, this owner
		// must revoke the minted binding itself, before any store pin release.
		if assets == nil && mintAttempted {
			if store == nil || binding.ID == "" {
				return errors.New("fixed mint outcome uncertain; store retained")
			}
			if err := store.Revoke(binding.ID); err != nil && !errors.Is(err, sandboxauth.ErrNotFound) {
				return errors.New("fixed pre-producer binding revoke incomplete")
			}
		}
		if binding.ID != "" {
			record["binding_revoked"] = true
		}
		if err := auditFixture.close(cleanup); err != nil {
			return err
		}
		for _, image := range []**bridgeprocess.Image{&peer, &bwrap, &payload} {
			if *image != nil {
				if err := (*image).Close(); err != nil {
					return err
				}
				*image = nil
			}
		}
		for index, file := range sourceFiles {
			if file != nil {
				if err := file.Close(); err != nil {
					return err
				}
				sourceFiles[index] = nil
			}
		}
		for index, file := range workspace {
			if file != nil {
				if err := file.Close(); err != nil {
					return err
				}
				workspace[index] = nil
			}
		}
		for index, file := range hostDirs {
			if file != nil {
				if err := file.Close(); err != nil {
					return err
				}
				hostDirs[index] = nil
			}
		}
		for _, file := range []**os.File{&parent, &inputs} {
			if *file != nil {
				if err := (*file).Close(); err != nil {
					return err
				}
				*file = nil
			}
		}
		return nil
	})
	if owner == nil {
		t.Fatal("fixed retained cleanup inventory full before filesystem/native operations")
	}
	// A defer runs on Fatal/Goexit as well as return. The native fixture below
	// has no TempDir/recursive cleanup: its held store and all residue remain
	// owned if native stop, durable revocation or an exclusive close is unsure.
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		err := owner.Close(cleanup)
		t.Logf("CONTAINED_HOOK_CLEANUP_RESULT connector=%s resources_released=%t incomplete=%t", value.Name, err == nil, err != nil)
		if err != nil {
			t.Error("fixed exact resources remain retained for uncertain cleanup")
		}
	}()
	inputFD, err := unix.Open("native-hook-canary-inputs", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("fixed admitted input directory unavailable")
	}
	inputs = os.NewFile(uintptr(inputFD), "fixed-inputs")
	var inputInfo unix.Stat_t
	if unix.Fstat(inputFD, &inputInfo) != nil || inputInfo.Mode&unix.S_IFMT != unix.S_IFDIR || inputInfo.Mode&0777 != 0700 || inputInfo.Uid != uint32(os.Geteuid()) {
		t.Fatal("fixed input directory custody differs")
	}
	peer, err = containedImage(lifetime, inputs, "peer", containedPeerSHA, &sourceFiles)
	if err != nil {
		t.Fatal("fixed peer seal refused")
	}
	bwrap, err = containedImage(lifetime, inputs, "bubblewrap", containedBwrapSHA, &sourceFiles)
	if err != nil {
		t.Fatal("fixed bwrap seal refused")
	}
	payload, err = containedImage(lifetime, inputs, "payload", containedPayloadSHA, &sourceFiles)
	if err != nil {
		t.Fatal("fixed payload seal refused")
	}
	// The early owner releases these only after native/endpoint cleanup.
	decisions := make(chan SandboxHookDecision, 8)
	resolution := connector.ResolveSandboxHookContract(value.Name, value.Version)
	if resolution.Status != connector.HookCompatibilityKnown {
		t.Fatal("fixed fixture hook contract is no longer known")
	}
	runtimeIdentity := sandboxruntime.RuntimeIdentity{Runtime: sandboxruntime.Axis, Backend: "mxc", Driver: "bubblewrap", HostOS: "linux", ExecutionOS: "linux", Architecture: "amd64", Version: "36139fb98708b4cc021d1f20841ace231e058fa2", Artifact: sandboxruntime.ArtifactIdentity{Kind: sandboxruntime.ExecutableBundle, Digest: containedPeerSHA}}
	identity := sandboxruntime.SessionIdentity{Owner: "fixed-hook-contributor", ID: "fixed-contained-hook-" + value.Name, Name: "fixed-contained-hook-" + value.Name, Runtime: runtimeIdentity}
	harness := sandboxruntime.HarnessIdentity{Version: value.Version, HookContract: resolution.Contract.ContractID, Artifact: sandboxruntime.ArtifactIdentity{Kind: sandboxruntime.ExecutableBundle, Digest: containedPayloadSHA}}
	// MkdirTemp is retained on failure: do not register recursive test cleanup.
	path, err := os.MkdirTemp("", "native-hook-fixed-")
	if err != nil {
		t.Fatal("fixed private root creation failed")
	}
	parent, err = os.Open(path)
	if err != nil {
		t.Fatal("fixed private root pin failed")
	}
	if _, err := containedCreatorMount(parent); err != nil {
		t.Fatal("fixed creator mount refused")
	}
	for _, leaf := range []string{"work", "home", "tmp"} {
		if err := unix.Mkdirat(int(parent.Fd()), leaf, 0700); err != nil {
			t.Fatal("fixed workspace creation failed")
		}
	}
	for _, leaf := range []string{"work", "home", "tmp"} {
		fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal("fixed workspace pin failed")
		}
		workspace = append(workspace, os.NewFile(uintptr(fd), "fixed-workspace"))
	}
	// Direct equivalent of the ordinary ingress test fixture, with explicitly
	// retained host directories instead of t.TempDir automatic deletion. These
	// directories are NEVER guest mounts or public fixture evidence.
	if err := unix.Mkdirat(int(parent.Fd()), "gateway", 0700); err != nil {
		t.Fatal("fixed host data directory creation failed")
	}
	controlFD, err := unix.Openat(int(parent.Fd()), "gateway", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("fixed host data directory pin failed")
	}
	control := os.NewFile(uintptr(controlFD), "fixed-host-data")
	hostDirs = append(hostDirs, control)
	if err := unix.Mkdirat(controlFD, "sandboxes", 0700); err != nil {
		t.Fatal("fixed host binding directory creation failed")
	}
	storeFD, err := unix.Openat(controlFD, "sandboxes", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("fixed host binding directory pin failed")
	}
	hostDirs = append(hostDirs, os.NewFile(uintptr(storeFD), "fixed-host-bindings"))
	if err := auditFixture.prepare(lifetime, filepath.Join(path, "gateway")); err != nil {
		t.Fatal("fixed private generated v8 audit runtime preparation failed")
	}
	cfg := &config.Config{DataDir: filepath.Join(path, "gateway"), Gateway: config.GatewayConfig{Token: sandboxTestMasterToken}}
	cfg.Guardrail.Mode, cfg.Guardrail.Connector = "action", value.Name
	api = NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, auditFixture.store, auditFixture.logger, cfg)
	store, err = sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(cfg.DataDir), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal("fixed host binding store preparation failed")
	}
	if err := api.SetSandboxIngress(SandboxIngressConfig{Addr: "127.0.0.1:18971", Bindings: store, OnHookDecision: func(decision SandboxHookDecision) {
		select {
		case decisions <- decision:
		default:
		}
	}}); err != nil {
		t.Fatal("fixed existing ingress configuration failed")
	}
	mintAttempted = true
	record["binding_mint_attempted"] = true
	binding, token, err = store.Mint(sandboxauth.Spec{SandboxID: identity.ID, SandboxName: identity.Name, Connector: value.Name, AgentVersion: value.Version, HookContractID: harness.HookContract, ExecutionOS: "linux", PolicyProfile: "open", Routes: []sandboxauth.Route{sandboxauth.RouteHook}, Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}, TTL: 30 * time.Second})
	if err != nil {
		t.Fatal("fixed host binding mint failed; retain uncertain store")
	}
	record["binding_issued"], record["binding_id"] = true, binding.ID
	assets, err = api.newNativeSandboxHookAssets(lifetime, identity, harness, "", binding.ID, token, parent)
	if assets == nil {
		t.Fatal("fixed producer owner unavailable")
	}
	if err != nil {
		t.Fatal("fixed hook producer preparation failed")
	}
	spec := sandboxruntime.Spec{Identity: identity, Harness: value.Name, HarnessIdentity: harness, BindingID: binding.ID, GuestWorkspace: "/work", Offline: true}
	_, err = assets.prepare(lifetime, spec, []string{bridgeproto.HookDirectory}, func(ctx context.Context, grant *os.File, hook *bridgeproto.Hook) (sandboxruntime.PreparedProcess, error) {
		process = &containedHookProcess{identity: identity, grant: grant}
		plan := bridgeproto.Preparation{Backend: "bubblewrap", Argv: []string{"/.defenseclaw/payload", value.Name}, Workdir: "/work", Environment: []bridgeproto.Variable{{Name: "HOME", Value: "/home"}, {Name: "TMPDIR", Value: "/tmp"}, {Name: "LANG", Value: "C.UTF-8"}, {Name: "LC_ALL", Value: "C.UTF-8"}}, Filesystem: bridgeproto.Filesystem{Read: []string{bridgeproto.HookDirectory}, Write: []string{"/work", "/home", "/tmp"}, Deny: []string{}}, Offline: true, TimeoutMS: 30000, OutputLimit: 128 << 10, Hook: hook}
		preparation, err := bridgeproto.PreparationDigest(plan)
		if err != nil {
			return process, err
		}
		process.binding = bridgeproto.Binding{SessionID: identity.ID, SessionDigest: containedDigest(identity), PolicyDigest: containedDigest(struct {
			Scope string
			Plan  bridgeproto.Preparation
		}{"fixed synthetic hook grant plan, no common policy receipt", plan}), RuntimeDigest: containedDigest(runtimeIdentity), HarnessDigest: containedDigest(harness), PreparationHash: preparation}
		owned, cancelOwned, stopPrepare, err := containedSessionLifetime(ctx, lifetime)
		if err != nil {
			return process, err
		}
		process.cancelSession = cancelOwned
		defer stopPrepare()
		process.session, err = bridgeprocess.Start(owned, process.binding, plan, bridgeprocess.Inputs{Peer: peer, Bubblewrap: bwrap, Payload: payload, CWD: workspace[0], Read: []*os.File{grant}, Write: workspace}, bridgeowner.Limits{WriteTimeout: 5 * time.Second, CleanupTimeout: 10 * time.Second})
		if err != nil {
			return process, err
		}
		request, err := process.session.Protocol.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Prepare, Plan: &plan})
		if err != nil {
			return process, err
		}
		frame, err := process.session.Protocol.Receive(ctx)
		if err != nil || frame.Kind != bridgeproto.Prepared || frame.Request != request || frame.Binding != process.binding {
			return process, errors.New("fixed Prepared correlation differs")
		}
		record["prepared"] = true
		return process, nil
	})
	if err != nil {
		t.Fatal("fixed actual peer preparation failed")
	}
	if _, err := assets.Launch(lifetime, spec); err != nil {
		if process == nil || process.launchObservation.Step == "" {
			record["native_launch_observation"] = containedLaunchObservation{Step: "assets_admission", OwnerError: containedKnownError(err)}
		}
		t.Fatal("fixed actual native launch failed")
	}
	record["started"] = true
	ready, err := process.row(lifetime)
	if err != nil || ready.Phase != "ready" {
		t.Fatal("fixed payload readiness differs")
	}
	for _, phase := range []byte{'A', 'B', 'S', 'L'} {
		if phase == 'L' {
			assets.seal()
		}
		if _, err := process.session.Protocol.Send(lifetime, bridgeowner.Command{Kind: bridgeproto.Input, Data: &bridgeproto.Data{Stream: "stdin", Bytes: []byte{phase}}}); err != nil {
			t.Fatal("fixed phase send failed")
		}
		row, err := process.row(lifetime)
		if err != nil || row.Phase != string(phase) {
			t.Fatal("fixed phase correlation differs")
		}
		rows = append(rows, row)
		t.Logf("fixed %s phase %c: helper code=%d stdout=%dB stderr=%dB; response semantics are not vendor enforcement", value.Name, phase, row.Code, len(row.Stdout), len(row.Stderr))
		if phase == 'A' || phase == 'B' {
			want := "allow"
			if phase == 'B' {
				want = "block"
			}
			var decision SandboxHookDecision
			select {
			case decision = <-decisions:
				if decision.BindingID != binding.ID || decision.SandboxName != identity.Name || decision.Connector != value.Name || decision.Action != want || decision.WouldBlock {
					t.Fatal("actual shared evaluator/binding differs")
				}
			case <-lifetime.Done():
				t.Fatal("actual shared evaluator decision absent")
			}
			// Retain the actual observer value, including its owner binding,
			// rather than synthesizing a verdict from a helper/HTTP status.
			observed = append(observed, decision)
			if value.Name == "claudecode" && fixture.ValidateClaudeRow(phase, row) != nil {
				t.Fatal("existing Claude helper response differs from actual shared decision")
			}
		} else {
			select {
			case <-decisions:
				t.Fatal("silence/closed admission produced a policy decision")
			default:
			}
			if value.Name == "claudecode" && phase == 'L' && fixture.ValidateClaudeRow(phase, row) != nil {
				t.Fatal("closed admission differs from existing Claude strict-client response")
			}
		}
	}
	if _, err := process.session.Protocol.Send(lifetime, bridgeowner.Command{Kind: bridgeproto.InputEOF}); err != nil {
		t.Fatal("fixed EOF failed")
	}
	terminal, err := process.session.Protocol.Receive(lifetime)
	if err != nil || terminal.Kind != bridgeproto.Exited || terminal.Request != process.launchRequest || terminal.Binding != process.binding || terminal.Result == nil || terminal.Result.ExitCode != 23 || terminal.Result.TimedOut || terminal.Result.Truncated {
		t.Fatal("actual payload terminal differs")
	}
	record["exited"] = true
	request, err := process.session.Protocol.Send(lifetime, bridgeowner.Command{Kind: bridgeproto.Destroy})
	if err != nil {
		t.Fatal("fixed Destroy failed")
	}
	destroyed, err := process.session.Protocol.Receive(lifetime)
	if err != nil || destroyed.Kind != bridgeproto.Destroyed || destroyed.Request != request || destroyed.Binding != process.binding {
		t.Fatal("actual Destroyed differs")
	}
	record["destroyed"] = true
	if len(observed) != 2 || observed[0].Action != "allow" || observed[1].Action != "block" ||
		auditFixture.rows(value.Name, observed[0].Event, observed[1].Event) != nil {
		t.Fatal("actual allow/block connector audit rows not durable")
	}
	record["audit_allow_and_block_durable"] = true
	cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if owner.Close(cleanup) != nil || !process.complete {
		t.Fatal("actual owned native/endpoint cleanup incomplete")
	}
	if _, err := store.Match(token); err == nil {
		t.Fatal("host binding remained live")
	}
	// Leave known empty directories for the reviewed collector; never recurse.
	t.Log("synthetic hook schema: actual shared allow/block, silence observed, admission loss observed, native cleanup complete; vendor veto/registration/production remain false")
}

func containedMountStatus(statxMask uint32, mountID uint64, response []byte) error {
	if statxMask&unix.STATX_MNT_ID_UNIQUE == 0 || mountID == 0 || len(response) < 72 ||
		binary.LittleEndian.Uint32(response[:4]) < 72 || uint64(binary.LittleEndian.Uint32(response[:4])) > uint64(len(response)) ||
		binary.LittleEndian.Uint64(response[8:16])&2 == 0 || // STATMOUNT_MNT_BASIC
		binary.LittleEndian.Uint64(response[40:48]) != mountID ||
		binary.LittleEndian.Uint64(response[64:72])&unix.MOUNT_ATTR_IDMAP != 0 {
		return errors.New("fixed creator-namespace non-idmapped source proof refused")
	}
	return nil
}

func containedCreatorMount(file *os.File) (uint64, error) {
	if file == nil {
		return 0, errors.New("fixed source mount capability absent")
	}
	var identity unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID_UNIQUE, &identity); err != nil {
		return 0, err
	}
	if identity.Mask&unix.STATX_MNT_ID_UNIQUE == 0 || identity.Mnt_id == 0 {
		return 0, errors.New("fixed source unique mount identity unavailable")
	}
	// Linux's version0 request is 24 bytes. An unset namespace selector means
	// this creator's CURRENT mount namespace; no foreign lookup or setns occurs.
	request := struct {
		Size, Spare uint32
		Mount, Mask uint64
	}{Size: 24, Mount: identity.Mnt_id, Mask: 2} // STATMOUNT_MNT_BASIC
	var response [512]byte
	_, _, errno := unix.Syscall6(unix.SYS_STATMOUNT, uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&response[0])), uintptr(len(response)), 0, 0, 0)
	runtime.KeepAlive(file)
	if errno != 0 {
		return 0, errno
	}
	if err := containedMountStatus(identity.Mask, identity.Mnt_id, response[:]); err != nil {
		return 0, err
	}
	return identity.Mnt_id, nil
}
