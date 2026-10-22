// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The lifecycle keeps a receipt event until the reporter marked it; both
// must name the same marker.
func TestBundleReceiptReporterMarkIsWhatTheLifecycleReads(t *testing.T) {
	for _, id := range []string{"b-01JA0000000000000000000042", "c-01JB8Z4X6T2Q9V3M5N7P1R0S4W"} {
		t.Run(id, func(t *testing.T) {
			dataDir := t.TempDir()
			r := &bundleReceiptReporter{markerPath: filepath.Join(dataDir, bundleReceiptMarkerName)}
			reported := enterprisestatus.ReceiptEventReported
			if enterprisestatus.ValidChangeEventID(id) {
				reported = enterprisestatus.ChangeReported
			}
			if reported(dataDir, id) || r.hasSeen(id) {
				t.Fatal("an unmarked event reads as reported")
			}
			if err := os.MkdirAll(r.seenDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(r.seenDir(), id), []byte("reported\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if reported(dataDir, id) || r.hasSeen(id) {
				t.Fatal("an enqueue-only legacy marker suppresses replay")
			}
			r.markSeen(id)
			if !reported(dataDir, id) || !r.hasSeen(id) {
				t.Fatal("the lifecycle does not see the reporter's confirmed marker")
			}
		})
	}
}
