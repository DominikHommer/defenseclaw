// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// writePathTokenFile is a tiny helper that mirrors what
// connector.EnsureOTLPPathToken writes — an owner-only file containing a
// hex-encoded token plus trailing newline — without taking the package-
// local mutex. We want the test to model the on-disk state the way
func writePathTokenFile(t *testing.T, dataDir string, scope connector.OTLPPathTokenScope, token string) string {
	t.Helper()
	dir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir hooks dir: %v", err)
	}
	path, err := connector.OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		t.Fatalf("OTLPPathTokenFilePath: %v", err)
	}
	if err := safefile.WritePrivate(path, []byte(token+"\n")); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func TestLookupOTLPPathToken_DetectsSameMtimeAtomicReplacement(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	original := strings.Repeat("a", 64)
	rotated := strings.Repeat("b", 64)
	path := writePathTokenFile(t, tmp, connector.OTLPScopeCodex, original)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat original token: %v", err)
	}
	cfg := &config.Config{DataDir: tmp}
	cfg.Gateway.Token = "gateway-master"
	api := &APIServer{scannerCfg: cfg}
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{connector.OTLPScopeCodex: original})
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != original {
		t.Fatal("initial token lookup failed")
	}

	temp := path + ".replacement"
	if err := os.WriteFile(temp, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Chtimes(temp, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("preserve replacement mtime: %v", err)
	}
	if err := os.Rename(temp, path); err != nil {
		t.Fatalf("atomic replacement: %v", err)
	}
	expireOTLPTokenValidation(t, api, connector.OTLPScopeCodex)
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != rotated {
		t.Fatal("same-mtime atomic replacement did not rotate cached token")
	}
	assertScopedOTLPAuth(t, api, original, http.StatusUnauthorized)
	assertScopedOTLPAuth(t, api, rotated, http.StatusOK)
}

func TestLookupOTLPPathToken_DetectsDeleteRecreateWithoutIntermediateLookup(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	original := strings.Repeat("c", 64)
	rotated := strings.Repeat("d", 64)
	path := writePathTokenFile(t, tmp, connector.OTLPScopeCodex, original)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat original token: %v", err)
	}
	cfg := &config.Config{DataDir: tmp}
	cfg.Gateway.Token = "gateway-master"
	api := &APIServer{scannerCfg: cfg}
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{connector.OTLPScopeCodex: original})
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != original {
		t.Fatal("initial token lookup failed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("delete token: %v", err)
	}
	if err := os.WriteFile(path, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatalf("recreate token: %v", err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("preserve recreated mtime: %v", err)
	}
	// No lookup occurs between delete and recreate.
	expireOTLPTokenValidation(t, api, connector.OTLPScopeCodex)
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != rotated {
		t.Fatal("delete+recreate did not rotate cached token")
	}
	assertScopedOTLPAuth(t, api, original, http.StatusUnauthorized)
	assertScopedOTLPAuth(t, api, rotated, http.StatusOK)
}

func TestLookupOTLPPathToken_RejectsSymlinkReplacement(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	original := strings.Repeat("e", 64)
	rotated := strings.Repeat("f", 64)
	path := writePathTokenFile(t, tmp, connector.OTLPScopeCodex, original)
	cfg := &config.Config{DataDir: tmp}
	cfg.Gateway.Token = "gateway-master"
	api := &APIServer{scannerCfg: cfg}
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{connector.OTLPScopeCodex: original})
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != original {
		t.Fatal("initial token lookup failed")
	}
	target := filepath.Join(tmp, "attacker-token")
	if err := os.WriteFile(target, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove token for symlink replacement: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		if os.IsPermission(err) || (runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314))) {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		t.Fatalf("replace token with symlink: %v", err)
	}
	expireOTLPTokenValidation(t, api, connector.OTLPScopeCodex)
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != "" {
		t.Fatal("symlink replacement retained or loaded an authorized token")
	}
	assertScopedOTLPAuth(t, api, original, http.StatusUnauthorized)
	assertScopedOTLPAuth(t, api, rotated, http.StatusUnauthorized)
}

func expireOTLPTokenValidation(t *testing.T, api *APIServer, scope connector.OTLPPathTokenScope) {
	t.Helper()
	api.otlpPathTokenMu.Lock()
	api.otlpPathTokenLastStatAt[scope] = time.Now().Add(-2 * otlpPathTokenStatMinInterval)
	api.otlpPathTokenMu.Unlock()
}

func assertScopedOTLPAuth(t *testing.T, api *APIServer, token string, want int) {
	t.Helper()
	called := false
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodPost, "/otlp/codex/"+token+"/v1/logs", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("scoped token auth status=%d want=%d", response.Code, want)
	}
	if called != (want == http.StatusOK) {
		t.Fatalf("scoped token handler called=%v want=%v", called, want == http.StatusOK)
	}
}

func TestLookupOTLPPathToken_ConcurrentDueRemovalNeverReturnsStale(t *testing.T) {
	const workers = 64
	for attempt := 0; attempt < 20; attempt++ {
		tmp := t.TempDir()
		minted := strings.Repeat(string(rune('a'+attempt%6)), 64)
		path := writePathTokenFile(t, tmp, connector.OTLPScopeCodex, minted)
		cfg := &config.Config{DataDir: tmp}
		cfg.Gateway.Token = "gateway-master"
		api := &APIServer{scannerCfg: cfg}
		api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{
			connector.OTLPScopeCodex: minted,
		})
		if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != minted {
			t.Fatalf("attempt %d initial lookup=%q want minted token", attempt, got)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("attempt %d remove token: %v", attempt, err)
		}
		expireOTLPTokenValidation(t, api, connector.OTLPScopeCodex)

		start := make(chan struct{})
		results := make(chan string, workers)
		var wg sync.WaitGroup
		wg.Add(workers)
		for range workers {
			go func() {
				defer wg.Done()
				<-start
				results <- api.lookupOTLPPathToken(string(connector.OTLPScopeCodex))
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		for got := range results {
			if got != "" {
				t.Fatalf("attempt %d concurrent due lookup returned revoked token %q", attempt, got)
			}
		}
	}
}
