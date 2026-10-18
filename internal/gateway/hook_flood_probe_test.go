// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// TestHookFloodProbe drives the real Claude Code hook handler, audit store and
// v8 runtime in process with one session at a fixed rate, the shape of the
// B-26 flood cells (rel-1-0-3 GAP-0247, GAP-0186, GAP-0244). It is skipped
// unless DEFENSECLAW_HOOK_FLOOD_PROBE=1 and runs on Linux, macOS and Windows,
// so a lane can run the test binary on the host that saturated. Settings:
//
//	DEFENSECLAW_HOOK_FLOOD_CALLS  calls per flood (default 6000)
//	DEFENSECLAW_HOOK_FLOOD_RATE   calls per second (default 10)
//	DEFENSECLAW_HOOK_FLOOD_FLOODS back-to-back floods in one process (default 1)
//	DEFENSECLAW_HOOK_FLOOD_IDLE   idle seconds after each flood (default 0)
//	DEFENSECLAW_HOOK_FLOOD_OUT    directory for cpu, block, mutex and heap profiles
//	DEFENSECLAW_HOOK_FLOOD_ASSERT 1: fail unless the last 600-call segment's average
//	                              and p99 are within 1.25x (+20 ms) of the first
func TestHookFloodProbe(t *testing.T) {
	if os.Getenv("DEFENSECLAW_HOOK_FLOOD_PROBE") != "1" {
		t.Skip("set DEFENSECLAW_HOOK_FLOOD_PROBE=1 to run the hook flood probe")
	}
	setting := func(name string, value int) int {
		if raw := os.Getenv("DEFENSECLAW_HOOK_FLOOD_" + name); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				t.Fatalf("DEFENSECLAW_HOOK_FLOOD_%s=%q is not a count", name, raw)
			}
			return parsed
		}
		return value
	}
	calls, rate := setting("CALLS", 6000), setting("RATE", 10)
	floods, idle := setting("FLOODS", 1), setting("IDLE", 0)
	if calls < 600 || rate < 1 || floods < 1 {
		t.Fatal("the probe needs at least 600 calls, a rate and one flood")
	}
	out := os.Getenv("DEFENSECLAW_HOOK_FLOOD_OUT")

	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	cwd := t.TempDir()

	// The sidecar's background audit loops: the WAL guard every 2 s and the
	// planner statistics every auditPlannerStatsInterval.
	ctx, cancel := context.WithCancel(t.Context())
	var loops sync.WaitGroup
	defer func() { cancel(); loops.Wait() }()
	loops.Add(2)
	go func() {
		defer loops.Done()
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			pass, passCancel := context.WithTimeout(ctx, 2*time.Minute)
			_, _ = fixture.store.CheckpointWALIfLarge(pass, 256<<20, 200*time.Millisecond)
			passCancel()
		}
	}()
	go func() {
		defer loops.Done()
		tick := time.NewTicker(auditPlannerStatsInterval)
		defer tick.Stop()
		for {
			_, _ = fixture.store.RefreshPlannerStatistics(ctx)
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()

	// The runtime's estimate of the CPU time it used: every CPU class but idle.
	cpuSample := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}, {Name: "/cpu/classes/idle:cpu-seconds"}}
	cpuSeconds := func() float64 {
		metrics.Read(cpuSample)
		if cpuSample[0].Value.Kind() != metrics.KindFloat64 || cpuSample[1].Value.Kind() != metrics.KindFloat64 {
			return 0
		}
		return cpuSample[0].Value.Float64() - cpuSample[1].Value.Float64()
	}
	fileSize := func(path string) int64 {
		info, err := os.Stat(path)
		if err != nil {
			return 0
		}
		return info.Size()
	}
	memory := func(label string) {
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		t.Logf("memory %s heap_inuse=%dKiB heap_sys=%dKiB heap_released=%dKiB sys=%dKiB goroutines=%d",
			label, stats.HeapInuse>>10, stats.HeapSys>>10, stats.HeapReleased>>10, stats.Sys>>10, runtime.NumGoroutine())
	}
	writeProfile := func(name string, write func(*os.File) error) {
		if out == "" {
			return
		}
		file, err := os.Create(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := write(file); err != nil {
			t.Fatal(err)
		}
	}
	heapProfile := func(name string) {
		runtime.GC()
		writeProfile(name, func(file *os.File) error { return pprof.WriteHeapProfile(file) })
	}
	if out != "" {
		if err := os.MkdirAll(out, 0o700); err != nil {
			t.Fatal(err)
		}
		runtime.SetBlockProfileRate(int(100 * time.Microsecond))
		runtime.SetMutexProfileFraction(5)
		defer runtime.SetBlockProfileRate(0)
		defer runtime.SetMutexProfileFraction(0)
	}
	memory("start")
	heapProfile("heap-start.prof")

	const segment = 600
	for flood := 1; flood <= floods; flood++ {
		session := fmt.Sprintf("hook-flood-probe-%d", flood)
		latencies := make([]time.Duration, calls)
		var cpuFile *os.File
		startCPU := func(name string) {
			if out == "" {
				return
			}
			cpuFile, err = os.Create(filepath.Join(out, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := pprof.StartCPUProfile(cpuFile); err != nil {
				t.Fatal(err)
			}
		}
		stopCPU := func() {
			if cpuFile != nil {
				pprof.StopCPUProfile()
				_ = cpuFile.Close()
				cpuFile = nil
			}
		}
		startCPU(fmt.Sprintf("cpu-flood%d-first.prof", flood))
		var wg sync.WaitGroup
		start := time.Now()
		segmentCPU := cpuSeconds()
		for index := range calls {
			if wait := time.Until(start.Add(time.Duration(index) * time.Second / time.Duration(rate))); wait > 0 {
				time.Sleep(wait)
			}
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				body, _ := json.Marshal(map[string]any{
					"session_id": session, "transcript_path": filepath.Join(cwd, "transcript.jsonl"), "cwd": cwd,
					"hook_event_name": "PreToolUse", "tool_name": "Bash",
					"tool_use_id": fmt.Sprintf("toolu_%d_%06d", flood, index),
					"tool_input":  map[string]any{"command": "echo ok"},
				})
				began := time.Now()
				recorder := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(recorder,
					httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
				latencies[index] = time.Since(began)
			}(index)
			if index == calls/6 {
				stopCPU()
			}
			if index == calls-calls/6 {
				startCPU(fmt.Sprintf("cpu-flood%d-last.prof", flood))
			}
			if (index+1)%segment == 0 {
				now := cpuSeconds()
				t.Logf("flood %d sent %d audit.db=%d wal=%d cpu_per_call=%.1fms", flood, index+1,
					fileSize(fixture.path), fileSize(fixture.path+"-wal"), (now-segmentCPU)*1000/segment)
				segmentCPU = now
			}
		}
		wg.Wait()
		stopCPU()
		t.Logf("flood %d drained %v after the first call", flood, time.Since(start).Round(time.Millisecond))
		type stats struct{ average, p99 time.Duration }
		var segments []stats
		for first := 0; first+segment <= calls; first += segment {
			part := slices.Clone(latencies[first : first+segment])
			slices.Sort(part)
			var sum time.Duration
			for _, latency := range part {
				sum += latency
			}
			s := stats{average: sum / segment, p99: part[segment*99/100]}
			segments = append(segments, s)
			t.Logf("flood %d calls %d-%d average=%v p50=%v p99=%v max=%v", flood, first, first+segment,
				s.average.Round(time.Microsecond), part[segment/2].Round(time.Microsecond),
				s.p99.Round(time.Microsecond), part[segment-1].Round(time.Microsecond))
		}
		memory(fmt.Sprintf("flood%d-end", flood))
		for waited := 0; waited < idle; waited += 60 {
			pause := min(60, idle-waited)
			time.Sleep(time.Duration(pause) * time.Second)
			memory(fmt.Sprintf("flood%d-idle+%ds", flood, waited+pause))
		}
		heapProfile(fmt.Sprintf("heap-flood%d.prof", flood))
		if os.Getenv("DEFENSECLAW_HOOK_FLOOD_ASSERT") == "1" {
			first, last := segments[0], segments[len(segments)-1]
			bound := func(d time.Duration) time.Duration { return d*5/4 + 20*time.Millisecond }
			if last.average > bound(first.average) || last.p99 > bound(first.p99) {
				t.Errorf("flood %d is not flat: last segment average %v p99 %v, first %v %v",
					flood, last.average, last.p99, first.average, first.p99)
			}
		}
	}
	writeProfile("block.prof", func(file *os.File) error { return pprof.Lookup("block").WriteTo(file, 0) })
	writeProfile("mutex.prof", func(file *os.File) error { return pprof.Lookup("mutex").WriteTo(file, 0) })
}
