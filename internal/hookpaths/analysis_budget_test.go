// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestShellAnalysisWorkLimit(t *testing.T) {
	skipWindowsShellFixture(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := filepath.Join(home, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	var assignments strings.Builder
	for i := range 500 {
		fmt.Fprintf(&assignments, "v%d=value%d; ", i, i)
	}
	rows := []struct {
		name, command string
		limit         bool
	}{
		{"brace_range", `printf '%s\n' {1..100000} > out.txt`, true},
		{"assignment_list", assignments.String() + `printf ok > out.txt`, true},
		{"nested_braces", `printf '%s\n' {a,b,c,d,e,f,g,h,i,j}{a,b,c,d,e,f,g,h,i,j}{a,b,c,d,e,f,g,h,i,j}{a,b,c,d,e,f,g,h,i,j} > out.txt`, true},
		{"small_range", `printf '%s\n' {1..30} > out.txt`, false},
		{"small_list", `v=out; printf ok > "$v"/file.txt`, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			encoded := Resolve(payload)
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			facts, ok := Decode(encoded)
			if !ok {
				t.Fatal("invalid analysis evidence")
			}
			_, limited := facts[TruncatedKey]
			if limited != row.limit {
				t.Fatalf("incomplete=%v, want %v", limited, row.limit)
			}
			if row.limit {
				if elapsed >= time.Second || after.TotalAlloc-before.TotalAlloc >= 100<<20 {
					t.Fatalf("analysis exceeded work limit: duration=%s allocated=%d", elapsed, after.TotalAlloc-before.TotalAlloc)
				}
			}
		})
	}
}

func TestShellAnalysisStaticWriteListBudget(t *testing.T) {
	var command strings.Builder
	for i := range 700 {
		fmt.Fprintf(&command, "printf verify > build/v%04d.txt; ", i)
	}
	budget := newShellAnalysisBudget()
	_, ok, limited := parseShellWithinBudget(command.String(), &budget)
	if !ok || limited {
		t.Fatalf("literal write list limited=%v nodes=%d bytes=%d assignments=%d", limited, budget.nodes, budget.bytes, budget.assignments)
	}
}
