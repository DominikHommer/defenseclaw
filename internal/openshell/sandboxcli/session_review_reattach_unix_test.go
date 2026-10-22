// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sandboxcli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestSessionAttachmentTakesGatewayRollbackLock(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := openshell.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := openshell.LockGatewayLifecycle(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ta := newTestApp(t, "")
	if release, err := ta.holdSession(t.Context(), "box"); !errors.Is(err, openshell.ErrGatewayBusy) {
		if release != nil {
			release()
		}
		t.Fatalf("session attached during gateway rollback: %v", err)
	}
}

type stalledFinishAPI struct {
	API
	started chan struct{}
	proceed chan struct{}
}

func (a *stalledFinishAPI) Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
	close(a.started)
	<-a.proceed
	return a.API.Stop(ctx, name)
}

func (a *stalledFinishAPI) Delete(ctx context.Context, name string, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	close(a.started)
	<-a.proceed
	return a.API.Delete(ctx, name, req)
}

// GAP-0455: the finish decision owns admission through the API call. A
// second terminal cannot create a lease after the zero recount but before
// Stop or Delete finishes.
func TestFinishAdmissionExcludesNewSessionUntilStopOrDeleteCompletes(t *testing.T) {
	for _, remove := range []bool{false, true} {
		ta := newTestApp(t, "")
		sb := sampleSandbox("finish-box")
		sb.Phase = "ready"
		ta.daemon.add(sb)
		api := &stalledFinishAPI{API: ta.daemon.client(), started: make(chan struct{}), proceed: make(chan struct{})}
		s := session{app: ta.App, api: api, sb: &sb, started: true, rm: remove}
		finished := make(chan error, 1)
		go func() { finished <- s.finish(context.Background(), false) }()
		select {
		case <-api.started:
		case <-time.After(5 * time.Second):
			t.Fatal("finish did not reach Stop or Delete")
		}
		attached := make(chan error, 1)
		go func() {
			release, err := ta.holdSession(context.Background(), sb.Name)
			if err == nil {
				release()
			}
			attached <- err
		}()
		select {
		case err := <-attached:
			t.Fatalf("new session entered during finish (rm=%v): %v", remove, err)
		case <-time.After(100 * time.Millisecond):
		}
		close(api.proceed)
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-attached:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("new session did not resume after finish")
		}
	}
}

func TestMountedReviewStopRecountsAndHoldsSessionAdmission(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("mounted-review-box")
	sb.Phase = "ready"
	ta.daemon.add(sb)
	s := session{app: ta.App, api: ta.daemon.client(), sb: &sb, started: true}
	// The end-of-harness count can be zero before a second terminal attaches.
	s.others = ta.attachedSessions(sb.Name)
	release := holdTestSession(t, ta, sb.Name)
	_, others, stopErr, admissionErr := s.stopMountedBeforeReview(t.Context())
	if others != 1 || stopErr != nil || admissionErr != nil || ta.calls("POST", sb.Name+"/stop") != 0 {
		t.Fatalf("mounted review stopped a newly attached session: others=%d, stop=%v, admission=%v, calls=%v", others, stopErr, admissionErr, ta.daemon.calls)
	}
	release()

	api := &stalledFinishAPI{API: ta.daemon.client(), started: make(chan struct{}), proceed: make(chan struct{})}
	s.api = api
	type result struct {
		others int
		stop   error
		gate   error
	}
	finished := make(chan result, 1)
	go func() {
		_, others, stop, gate := s.stopMountedBeforeReview(context.Background())
		finished <- result{others, stop, gate}
	}()
	select {
	case <-api.started:
	case <-time.After(5 * time.Second):
		t.Fatal("mounted review did not reach Stop")
	}
	attached := make(chan error, 1)
	go func() {
		release, err := ta.holdSession(context.Background(), sb.Name)
		if err == nil {
			release()
		}
		attached <- err
	}()
	select {
	case err := <-attached:
		t.Fatalf("new session entered during mounted review Stop: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(api.proceed)
	if got := <-finished; got.others != 0 || got.stop != nil || got.gate != nil {
		t.Fatalf("mounted review Stop: %+v", got)
	}
	select {
	case err := <-attached:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("new session did not resume after mounted review Stop")
	}
}

func TestDirectStopAndDeleteExcludeNewSessionUntilAPICallCompletes(t *testing.T) {
	for _, remove := range []bool{false, true} {
		ta := newTestApp(t, "")
		sb := sampleSandbox("direct-box")
		sb.Phase = "ready"
		ta.daemon.add(sb)
		api := &stalledFinishAPI{API: ta.daemon.client(), started: make(chan struct{}), proceed: make(chan struct{})}
		ta.API = api
		finished := make(chan error, 1)
		go func() {
			if remove {
				finished <- ta.Delete(context.Background(), DeleteOptions{Names: []string{sb.Name}, Yes: true})
			} else {
				finished <- ta.Stop(context.Background(), StopOptions{Name: sb.Name, Yes: true})
			}
		}()
		select {
		case <-api.started:
		case <-time.After(5 * time.Second):
			t.Fatal("command did not reach Stop or Delete")
		}
		attached := make(chan error, 1)
		go func() {
			release, err := ta.holdSession(context.Background(), sb.Name)
			if err == nil {
				release()
			}
			attached <- err
		}()
		select {
		case err := <-attached:
			t.Fatalf("new session entered during direct command (rm=%v): %v", remove, err)
		case <-time.After(100 * time.Millisecond):
		}
		close(api.proceed)
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-attached:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("new session did not resume after direct command")
		}
	}
}

// The first session counted leases before opening its copy review. Another
// terminal attached while the question was open; completion must count it
// again before any stop or deletion.
func TestCopyReviewCompletionKeepsNewlyAttachedSession(t *testing.T) {
	for _, remove := range []bool{false, true} {
		ta := newTestApp(t, "")
		sb := sampleSandbox("review-box")
		sb.Phase = "ready"
		sb.WorkdirMode = config.OpenShellWorkdirCopy
		ta.daemon.add(sb)
		s := session{app: ta.App, api: ta.daemon.client(), sb: &sb, started: true, rm: remove}
		// This is the count taken before the first terminal's review prompt.
		s.others = ta.attachedSessions(sb.Name)
		release := holdTestSession(t, ta, sb.Name)
		if err := s.finish(bg, false); err != nil {
			release()
			t.Fatal(err)
		}
		release()
		if ta.calls("POST", sb.Name+"/stop") != 0 || ta.calls("DELETE", sb.Name) != 0 ||
			!strings.Contains(ta.output(), "other session is attached") {
			t.Fatalf("review completion stopped a new session (rm=%v): calls=%v, output=%s", remove, ta.daemon.calls, ta.output())
		}
	}
}
