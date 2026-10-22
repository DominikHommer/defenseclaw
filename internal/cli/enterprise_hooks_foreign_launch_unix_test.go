// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// waitEnterpriseHookLookupsDrained waits, up to five seconds, until no
// startEnterpriseHookLookup lookup whose key starts with kind runs, so a
// test can put back the seams such a lookup reads.
func waitEnterpriseHookLookupsDrained(kind string) {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		running := 0
		enterpriseHookLookupsMu.Lock()
		for key := range enterpriseHookLookups {
			if strings.HasPrefix(key, kind+"\x00") {
				running++
			}
		}
		enterpriseHookLookupsMu.Unlock()
		if running == 0 {
			return
		}
	}
}

// stallEnterpriseHookWorkerGroups makes worker launches resolve
// supplementary groups (as a root parent does) through a lookup that
// answers answer, after blocking until the test ends when stall is set,
// the way an Open Directory lookup on macOS can stall. A launch waits
// bound for it. entered gets one value per lookup that starts.
func stallEnterpriseHookWorkerGroups(t *testing.T, bound time.Duration, answer []int, stall bool) (<-chan struct{}, *atomic.Int32) {
	t.Helper()
	release := make(chan struct{})
	entered := make(chan struct{}, 16)
	calls := &atomic.Int32{}
	previousResolves, previousLookup := enterpriseHookWorkerResolvesGroups, enterpriseHookWorkerGroupIDs
	previousTimeout, previousLog := enterpriseHookWorkerGroupLookupTimeout, enterpriseHookWorkerLog
	t.Cleanup(func() {
		close(release)
		waitEnterpriseHookLookupsDrained("worker-groups")
		enterpriseHookWorkerResolvesGroups, enterpriseHookWorkerGroupIDs = previousResolves, previousLookup
		enterpriseHookWorkerGroupLookupTimeout, enterpriseHookWorkerLog = previousTimeout, previousLog
	})
	enterpriseHookWorkerResolvesGroups = func() bool { return true }
	enterpriseHookWorkerGroupLookupTimeout = bound
	enterpriseHookWorkerLog = io.Discard
	enterpriseHookWorkerGroupIDs = func(enterpriseHookWorkerAccount) []int {
		calls.Add(1)
		entered <- struct{}{}
		if stall {
			<-release
		}
		return answer
	}
	return entered, calls
}

// useForeignTxLaunchPass is useForeignTxPass whose worker sees the account
// it runs for: the planning worker plans a Cursor hook file, and the
// cleaning worker reports the launch the pool resolved for it and the
// pending denials in the ledger while it runs.
func useForeignTxLaunchPass(t *testing.T) (string, func() ([]*enterpriseHookWorkerLaunch, []string)) {
	t.Helper()
	dataDir := useForeignTxPass(t, nil)
	var mu sync.Mutex
	var launches []*enterpriseHookWorkerLaunch
	var pending []string
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		var response enterpriseHookWorkerResponse
		if foreignTxPlanning(request) {
			response = foreignTxPlan(map[string][]string{"cursor": {"/home/alice/.cursor/hooks.json"}})
		} else {
			mu.Lock()
			launches = append(launches, account.launch)
			pending = append(pending, foreignTxPendingConnectors(dataDir))
			mu.Unlock()
			response.Cleanup = map[string]enterpriseHookWorkerCleanupReport{"cursor": {}}
		}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true})
		}
		return response, nil
	}
	return dataDir, func() ([]*enterpriseHookWorkerLaunch, []string) {
		mu.Lock()
		defer mu.Unlock()
		return launches, pending
	}
}

func foreignTxOpenTransactions() int {
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	return len(enterpriseForeignHookCleanupTxs)
}

func waitForeignTx(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// A cleanup's pending denial lasts only while its worker runs: everything
// the worker launch looks up, the supplementary groups included, comes
// before the denial is published, and the lookup is bounded. A group lookup
// that stalls (Open Directory on macOS) published a denial for the account
// that no worker would ever settle while the guardian lived.
func TestForeignHookCleanupDenialWaitsForTheWorkerLaunch(t *testing.T) {
	t.Run("a stalled group lookup", func(t *testing.T) {
		dataDir, seen := useForeignTxLaunchPass(t)
		entered, _ := stallEnterpriseHookWorkerGroups(t, 300*time.Millisecond, []int{4242, 2000}, true)
		done := make(chan struct{})
		var log string
		go func() {
			defer close(done)
			log = runForeignTxPass(t)
		}()
		waitForeignTx(t, entered, "the group lookup")
		if got := foreignTxPendingConnectors(dataDir); got != "" || foreignTxOpenTransactions() != 0 {
			t.Fatalf("a denial (%q) was published while the worker's launch was still resolving", got)
		}
		waitForeignTx(t, done, "the pass")
		launches, pending := seen()
		if len(launches) != 1 || launches[0] == nil || launches[0].groups != nil || launches[0].exe == "" {
			t.Fatalf("the cleaning worker must start once the lookup is past its bound, with the primary group only: %+v; log:\n%s", launches, log)
		}
		if len(pending) != 1 || pending[0] != "cursor" {
			t.Fatalf("pending denials while the cleaning worker ran: %q", pending)
		}
		if got := foreignTxPendingConnectors(dataDir); got != "" || foreignTxOpenTransactions() != 0 {
			t.Fatalf("the pass left a pending denial (%q)", got)
		}
	})
	t.Run("the lookup answers", func(t *testing.T) {
		dataDir, seen := useForeignTxLaunchPass(t)
		stallEnterpriseHookWorkerGroups(t, 5*time.Second, []int{4242, 2000}, false)
		log := runForeignTxPass(t)
		launches, pending := seen()
		if len(launches) != 1 || launches[0] == nil || fmt.Sprint(launches[0].groups) != "[4242 2000]" {
			t.Fatalf("the worker must start with the groups resolved before the denial: %+v; log:\n%s", launches, log)
		}
		if len(pending) != 1 || pending[0] != "cursor" || foreignTxPendingConnectors(dataDir) != "" {
			t.Fatalf("pending denials while the worker ran %q, after %q", pending, foreignTxPendingConnectors(dataDir))
		}
	})
	t.Run("the pass ends during the lookup", func(t *testing.T) {
		dataDir, seen := useForeignTxLaunchPass(t)
		entered, _ := stallEnterpriseHookWorkerGroups(t, time.Minute, nil, true)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		var log bytes.Buffer
		go func() {
			defer close(done)
			runEnterpriseHookStandaloneForeignCleanup(ctx, &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{"alice": {"codex": true}}, "")
		}()
		waitForeignTx(t, entered, "the group lookup")
		cancel()
		waitForeignTx(t, done, "the pass")
		if launches, _ := seen(); len(launches) != 0 {
			t.Fatalf("a cleaning worker ran after its launch could not be resolved: %+v", launches)
		}
		if got := foreignTxPendingConnectors(dataDir); got != "" || foreignTxOpenTransactions() != 0 {
			t.Fatalf("a launch that never resolved left a pending denial (%q)", got)
		}
		if !strings.Contains(log.String(), errEnterpriseHookWorkerNotStarted.Error()) {
			t.Fatalf("the unresolved launch must be reported; log:\n%s", log.String())
		}
	})
	t.Run("a stalled directory gets one lookup per account", func(t *testing.T) {
		entered, calls := stallEnterpriseHookWorkerGroups(t, 100*time.Millisecond, nil, true)
		account := enterpriseHookWorkerAccount{UID: 4242, GID: 4242, User: "alice", Home: "/home/alice"}
		for range 3 {
			started := time.Now()
			launch, err := resolveEnterpriseHookWorkerLaunch(context.Background(), account)
			if err != nil || launch == nil || launch.groups != nil {
				t.Fatalf("a stalled lookup must fall back to the primary group: %+v, %v", launch, err)
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("the launch waited %s for a stalled lookup", elapsed)
			}
		}
		waitForeignTx(t, entered, "the group lookup")
		if got := calls.Load(); got != 1 {
			t.Fatalf("%d lookups ran for one stalled account", got)
		}
	})
	t.Run("the worker launch itself is bounded", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("runs the worker as the test's own non-root account")
		}
		trueBin, err := exec.LookPath("true")
		if err != nil {
			t.Skip("no true(1)")
		}
		previousExe := enterpriseHookWorkerExecutable
		t.Cleanup(func() { enterpriseHookWorkerExecutable = previousExe })
		enterpriseHookWorkerExecutable = func() (string, error) { return trueBin, nil }
		stallEnterpriseHookWorkerGroups(t, 200*time.Millisecond, nil, true)
		account := enterpriseHookWorkerAccount{UID: os.Getuid(), GID: os.Getgid(), User: "self", Home: t.TempDir()}
		started := time.Now()
		_, err = runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpForeignCleanup})
		if err == nil || errors.Is(err, errEnterpriseHookWorkerNotStarted) || time.Since(started) > 10*time.Second {
			t.Fatalf("the worker must start past a stalled lookup: %v after %s", err, time.Since(started))
		}
		// A launch the pool resolved is used as it is.
		enterpriseHookWorkerExecutable = func() (string, error) { return "", errors.New("must not be resolved again") }
		account.launch = &enterpriseHookWorkerLaunch{exe: trueBin, env: []string{"PATH=/usr/bin:/bin"}}
		if _, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpForeignCleanup}); err == nil || errors.Is(err, errEnterpriseHookWorkerNotStarted) {
			t.Fatalf("a resolved launch was not used: %v", err)
		}
	})
}

// A pending denial must name a guardian process a later pass can tell has
// ended. A denial without one, published when the guardian could not read
// its own process, was kept by every later pass: when the guardian died
// mid-cleanup, the account's agents (also of an account that reuses the
// uid) were denied forever.
func TestForeignHookCleanupRefusesAnOwnerItCannotSettle(t *testing.T) {
	goos, boot, start := foreignTxClock(t)
	for name, owner := range map[string]string{
		"self lookup failed": "",
		"malformed":          fmt.Sprintf("%s:%s:x:%d", goos, boot, start),
		"no start time":      fmt.Sprintf("%s:%s:10", goos, boot),
		"another system":     fmt.Sprintf("plan9:%s:10:%d", boot, start),
		"another boot":       fmt.Sprintf("%s:%sx:10:%d", goos, boot, start),
	} {
		t.Run(name, func(t *testing.T) {
			resetForeignTxs(t)
			dataDir := useUserCleanupStateDir(t)
			previous, previousOwner := cfg, enterpriseForeignHookCleanupOwner
			t.Cleanup(func() { cfg, enterpriseForeignHookCleanupOwner = previous, previousOwner })
			cfg = standaloneTestConfig(dataDir)
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"cursor": {}}
			enterpriseForeignHookCleanupOwner = func() string { return owner }
			token, err := beginEnterpriseForeignHookCleanup(io.Discard, "1000", []string{"cursor"})
			if err == nil || token != "" {
				t.Fatalf("a cleanup opened with owner %q: %q, %v", owner, token, err)
			}
			if _, statErr := os.Lstat(foreignTxLedger(dataDir)); !errors.Is(statErr, os.ErrNotExist) || foreignTxOpenTransactions() != 0 {
				t.Fatalf("a refused cleanup published a denial or left a transaction: %v", statErr)
			}
		})
	}
	t.Run("a pass whose guardian cannot name itself cleans nothing", func(t *testing.T) {
		workers := 0
		dataDir := useForeignTxPass(t, func(request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
			workers++
			if foreignTxPlanning(request) {
				return foreignTxPlan(map[string][]string{"cursor": {"/home/alice/.cursor/hooks.json"}}), nil
			}
			return enterpriseHookWorkerResponse{}, nil
		})
		previousOwner := enterpriseForeignHookCleanupOwner
		t.Cleanup(func() { enterpriseForeignHookCleanupOwner = previousOwner })
		enterpriseForeignHookCleanupOwner = func() string { return "" }
		log := runForeignTxPass(t)
		if workers != 1 || !strings.Contains(log, "refused before file removal") {
			t.Fatalf("a cleanup that could not name its owner ran %d workers; log:\n%s", workers, log)
		}
		if _, statErr := os.Lstat(foreignTxLedger(dataDir)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("a refused cleanup published a denial: %v", statErr)
		}
	})
	t.Run("this process's running cleanup keeps its denial", func(t *testing.T) {
		resetForeignTxs(t)
		dataDir := useUserCleanupStateDir(t)
		previous := cfg
		t.Cleanup(func() { cfg = previous })
		cfg = standaloneTestConfig(dataDir)
		cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"cursor": {}}
		token, err := beginEnterpriseForeignHookCleanup(io.Discard, "1000", []string{"cursor"})
		if err != nil {
			t.Fatal(err)
		}
		// Even dated past every bound: this process's worker may still run.
		entries := readForeignTxLedger(t, dataDir)
		for i := range entries {
			entries[i].At = time.Now().UTC().Add(-2 * enterpriseForeignHookPendingMaxAge).Format(time.RFC3339Nano)
		}
		writeForeignTxLedger(t, dataDir, entries)
		reconcileEnterpriseForeignHookCleanups(io.Discard)
		if pending := foreignTxPending(readForeignTxLedger(t, dataDir)); len(pending) != 1 || pending[0].Path != token {
			t.Fatalf("a running cleanup lost its denial: %+v", pending)
		}
		if err := finishEnterpriseForeignHookCleanup(io.Discard, token, false); err != nil {
			t.Fatal(err)
		}
		if pending := foreignTxPending(readForeignTxLedger(t, dataDir)); len(pending) != 0 {
			t.Fatalf("the finished cleanup kept its denial: %+v", pending)
		}
	})
}

// stallEnterpriseHookWorkerPath makes the worker PATH's directory check
// (enterpriseHookWorkerSearchDirs) answer /opt/agent/bin, after blocking
// until the test ends when stall is set, the way a Directory Services
// lookup on macOS can stall. A launch waits bound for it. entered gets a
// value when a check starts.
func stallEnterpriseHookWorkerPath(t *testing.T, bound time.Duration, stall bool) (<-chan struct{}, *atomic.Int32) {
	t.Helper()
	release := make(chan struct{})
	entered := make(chan struct{}, 16)
	calls := &atomic.Int32{}
	previousDirs, previousTimeout := enterpriseHookWorkerSearchDirs, enterpriseHookWorkerEnvironmentTimeout
	t.Cleanup(func() {
		close(release)
		waitEnterpriseHookLookupsDrained("worker-environment")
		enterpriseHookWorkerSearchDirs, enterpriseHookWorkerEnvironmentTimeout = previousDirs, previousTimeout
	})
	enterpriseHookWorkerEnvironmentTimeout = bound
	enterpriseHookWorkerSearchDirs = func(string, int) []string {
		calls.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		if stall {
			<-release
		}
		return []string{"/opt/agent/bin"}
	}
	return entered, calls
}

// foreignTxNoLedger fails the test when the guardian wrote a removal
// ledger: a refused cleanup publishes nothing.
func foreignTxNoLedger(t *testing.T, dataDir string) {
	t.Helper()
	if _, err := os.Lstat(foreignTxLedger(dataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a cleanup whose worker never started wrote the removal ledger (%v)", err)
	}
}

// A cleanup's pending denial is published only once its worker's whole
// environment is resolved. The worker's PATH takes a machine directory only
// after checking who can change it, which on macOS can ask Directory
// Services and stall. That check ran after the denial was published and
// outside the worker's timeout, so a stalled directory kept the denial for
// as long as the guardian lived. Now a PATH that does not resolve in time
// refuses the cleanup before anything is published, and once a launch is
// resolved the runner looks nothing up.
func TestForeignHookCleanupDenialWaitsForTheWorkerEnvironment(t *testing.T) {
	t.Run("a stalled PATH check refuses the cleanup", func(t *testing.T) {
		dataDir, seen := useForeignTxLaunchPass(t)
		entered, _ := stallEnterpriseHookWorkerPath(t, 300*time.Millisecond, true)
		done := make(chan struct{})
		var log string
		go func() {
			defer close(done)
			log = runForeignTxPass(t)
		}()
		waitForeignTx(t, entered, "the PATH check")
		if got := foreignTxPendingConnectors(dataDir); got != "" || foreignTxOpenTransactions() != 0 {
			t.Fatalf("a denial (%q) was published while the worker's PATH was still resolving", got)
		}
		waitForeignTx(t, done, "the pass")
		if launches, _ := seen(); len(launches) != 0 {
			t.Fatalf("a cleaning worker ran without its environment: %+v", launches)
		}
		foreignTxNoLedger(t, dataDir)
		if foreignTxOpenTransactions() != 0 {
			t.Fatal("a refused cleanup left a transaction")
		}
		if !strings.Contains(log, errEnterpriseHookWorkerNotStarted.Error()) || !strings.Contains(log, "did not resolve within") {
			t.Fatalf("the refused cleanup must be reported; log:\n%s", log)
		}
	})
	t.Run("the PATH check answers", func(t *testing.T) {
		dataDir, seen := useForeignTxLaunchPass(t)
		stallEnterpriseHookWorkerPath(t, 5*time.Second, false)
		log := runForeignTxPass(t)
		launches, pending := seen()
		if len(launches) != 1 || launches[0] == nil || !slices.Contains(launches[0].env, "PATH=/usr/bin:/bin:/opt/agent/bin") {
			t.Fatalf("the worker must start with the PATH resolved before the denial: %+v; log:\n%s", launches, log)
		}
		if len(pending) != 1 || pending[0] != "cursor" || foreignTxPendingConnectors(dataDir) != "" {
			t.Fatalf("pending denials while the worker ran %q, after %q", pending, foreignTxPendingConnectors(dataDir))
		}
	})
	t.Run("the pass ends during the PATH check", func(t *testing.T) {
		dataDir, seen := useForeignTxLaunchPass(t)
		entered, _ := stallEnterpriseHookWorkerPath(t, time.Minute, true)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		var log bytes.Buffer
		go func() {
			defer close(done)
			runEnterpriseHookStandaloneForeignCleanup(ctx, &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{"alice": {"codex": true}}, "")
		}()
		waitForeignTx(t, entered, "the PATH check")
		cancel()
		waitForeignTx(t, done, "the pass")
		if launches, _ := seen(); len(launches) != 0 {
			t.Fatalf("a cleaning worker ran after its launch could not be resolved: %+v", launches)
		}
		foreignTxNoLedger(t, dataDir)
		if !strings.Contains(log.String(), errEnterpriseHookWorkerNotStarted.Error()) {
			t.Fatalf("the unresolved launch must be reported; log:\n%s", log.String())
		}
	})
	t.Run("a stalled PATH check and a stalled group lookup", func(t *testing.T) {
		dataDir, seen := useForeignTxLaunchPass(t)
		stallEnterpriseHookWorkerGroups(t, 200*time.Millisecond, nil, true)
		stallEnterpriseHookWorkerPath(t, 200*time.Millisecond, true)
		started := time.Now()
		runForeignTxPass(t)
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("the pass waited %s for stalled lookups", elapsed)
		}
		if launches, _ := seen(); len(launches) != 0 {
			t.Fatalf("a cleaning worker ran without its environment: %+v", launches)
		}
		foreignTxNoLedger(t, dataDir)
	})
	t.Run("a stalled directory gets one PATH check per account", func(t *testing.T) {
		_, calls := stallEnterpriseHookWorkerPath(t, 100*time.Millisecond, true)
		account := enterpriseHookWorkerAccount{UID: 4242, GID: 4242, User: "alice", Home: "/home/alice"}
		for range 3 {
			started := time.Now()
			launch, err := resolveEnterpriseHookWorkerLaunch(context.Background(), account)
			if err == nil || launch != nil {
				t.Fatalf("a launch whose PATH did not resolve was resolved: %+v, %v", launch, err)
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("the launch waited %s for a stalled PATH check", elapsed)
			}
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("%d PATH checks ran for one stalled account", got)
		}
	})
	t.Run("the runner looks nothing up for a resolved launch", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("runs the worker as the test's own non-root account")
		}
		trueBin, err := exec.LookPath("true")
		if err != nil {
			t.Skip("no true(1)")
		}
		_, calls := stallEnterpriseHookWorkerPath(t, 5*time.Second, true)
		account := enterpriseHookWorkerAccount{UID: os.Getuid(), GID: os.Getgid(), User: "self", Home: t.TempDir()}
		request := enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpForeignCleanup}
		account.launch = &enterpriseHookWorkerLaunch{exe: trueBin}
		if _, err := runEnterpriseHookWorker(context.Background(), account, request); !errors.Is(err, errEnterpriseHookWorkerNotStarted) {
			t.Fatalf("a launch without its environment must not start: %v", err)
		}
		account.launch = &enterpriseHookWorkerLaunch{exe: trueBin, env: []string{"PATH=/usr/bin:/bin"}}
		if _, err := runEnterpriseHookWorker(context.Background(), account, request); err == nil || errors.Is(err, errEnterpriseHookWorkerNotStarted) {
			t.Fatalf("a resolved launch was not started: %v", err)
		}
		if got := calls.Load(); got != 0 {
			t.Fatalf("the runner checked the PATH %d times for a resolved launch", got)
		}
	})
	t.Run("a runner that resolves its own launch is bounded", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("runs the worker as the test's own non-root account")
		}
		stallEnterpriseHookWorkerPath(t, 200*time.Millisecond, true)
		account := enterpriseHookWorkerAccount{UID: os.Getuid(), GID: os.Getgid(), User: "self", Home: t.TempDir()}
		started := time.Now()
		_, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpForeignCleanup})
		if !errors.Is(err, errEnterpriseHookWorkerNotStarted) || time.Since(started) > 5*time.Second {
			t.Fatalf("a stalled PATH check must end the launch before the worker starts: %v after %s", err, time.Since(started))
		}
	})
}

// The service account lookup of a guardian record write is bounded, runs
// once per account however many writes wait on it, and its answer is kept:
// the write that settles a cleanup's pending denial reuses the group the
// write that published it found, and makes no directory call that could
// stall and keep the denial.
func TestEnterpriseHookServiceGroupLookupIsBoundedAndKept(t *testing.T) {
	const name = "_dc_test_service_group"
	release := make(chan struct{})
	var calls atomic.Int32
	previousLookup, previousTimeout := enterpriseHookServiceUserLookup, enterpriseHookServiceGroupLookupTimeout
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		waitEnterpriseHookLookupsDrained("service-group")
		enterpriseHookServiceUserLookup, enterpriseHookServiceGroupLookupTimeout = previousLookup, previousTimeout
		enterpriseHookServiceGroupsMu.Lock()
		delete(enterpriseHookServiceGroups, name)
		delete(enterpriseHookServiceGroups, name+"_unknown")
		enterpriseHookServiceGroupsMu.Unlock()
	})
	enterpriseHookServiceGroupLookupTimeout = 100 * time.Millisecond
	enterpriseHookServiceUserLookup = func(lookup string) (*user.User, error) {
		calls.Add(1)
		if lookup != name {
			return nil, user.UnknownUserError(lookup)
		}
		<-release
		return &user.User{Username: lookup, Gid: "4321"}, nil
	}
	for range 3 {
		started := time.Now()
		if _, err := enterpriseHookServiceGroup(name); err == nil || !strings.Contains(err.Error(), "did not resolve within") {
			t.Fatalf("a stalled service account lookup answered: %v", err)
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("a write waited %s for a stalled service account lookup", elapsed)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("%d lookups ran for one stalled service account", got)
	}
	close(release)
	waitEnterpriseHookLookupsDrained("service-group")
	if gid, err := enterpriseHookServiceGroup(name); err != nil || gid != 4321 {
		t.Fatalf("service group %d, %v; want 4321", gid, err)
	}
	enterpriseHookServiceUserLookup = func(string) (*user.User, error) {
		calls.Add(1)
		return nil, errors.New("the directory must not be asked again")
	}
	before := calls.Load()
	if gid, err := enterpriseHookServiceGroup(name); err != nil || gid != 4321 || calls.Load() != before {
		t.Fatalf("a found service group was looked up again: %d, %v", gid, err)
	}
	enterpriseHookServiceUserLookup = func(lookup string) (*user.User, error) { return nil, user.UnknownUserError(lookup) }
	for range 2 {
		var unknown user.UnknownUserError
		if _, err := enterpriseHookServiceGroup(name + "_unknown"); !errors.As(err, &unknown) {
			t.Fatalf("an unknown service account must be reported as one: %v", err)
		}
	}
	enterpriseHookServiceGroupsMu.Lock()
	_, kept := enterpriseHookServiceGroups[name+"_unknown"]
	enterpriseHookServiceGroupsMu.Unlock()
	if kept {
		t.Fatal("a failed lookup was kept")
	}
}

// The owner check refuses a record that is not root's and in the service
// group.
func TestEnterpriseHookRecordOwnershipIsVerified(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a file root does not own")
	}
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := verifyEnterpriseHookRecordOwnership(path, os.Getgid()); err == nil {
		t.Fatal("a record the test account owns passed the root owner check")
	}
}
