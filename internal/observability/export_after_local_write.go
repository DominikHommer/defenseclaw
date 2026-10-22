// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package observability

import "context"

type exportAfterLocalWriteKey struct{}

// exportAfterLocalWrite is the WithExportAfterLocalWrite mark.
type exportAfterLocalWrite struct {
	makeDurable func(context.Context) error
}

// WithExportAfterLocalWrite marks a log occurrence whose producer keeps it
// queued under a stable id and offers it again until the local store
// records it (a trust anchor or credential change event). Its optional
// destinations get it only once the local write succeeded: a failed write
// exports nothing, so a retry cannot export the same occurrence again, and
// the stable id keeps the retry after a success to one local row. Other
// occurrences are still exported when the local write fails (GAP-1536).
//
// makeDurable makes the stored row survive a power loss (the store commits
// with synchronous=NORMAL). The runtime runs it after the local write and
// before any optional destination gets the occurrence; when it fails no
// destination gets it, and an occurrence marked without one is refused.
// Otherwise a destination could acknowledge a record whose row a power
// loss takes back, and the next offer would send another record (another
// time, run and sidecar) under the same id.
func WithExportAfterLocalWrite(ctx context.Context, makeDurable func(context.Context) error) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, exportAfterLocalWriteKey{}, exportAfterLocalWrite{makeDurable: makeDurable})
}

// ExportAfterLocalWrite reports whether ctx carries WithExportAfterLocalWrite.
func ExportAfterLocalWrite(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	_, marked := ctx.Value(exportAfterLocalWriteKey{}).(exportAfterLocalWrite)
	return marked
}

// LocalDurabilityStep returns the makeDurable step of an occurrence marked
// WithExportAfterLocalWrite, or nil.
func LocalDurabilityStep(ctx context.Context) func(context.Context) error {
	if ctx == nil {
		return nil
	}
	mark, _ := ctx.Value(exportAfterLocalWriteKey{}).(exportAfterLocalWrite)
	return mark.makeDurable
}

type storedReplayKey struct{}

// WithStoredReplay marks an offer of an occurrence the local store already
// holds under its stable id (an earlier offer stored it, then a destination
// failed or the process stopped before every destination had it). stored
// is the projected record its local row holds (projected_record_json). The
// pipeline does not write the occurrence locally again; it hands back its
// optional-destination projections only when the rebuilt record is the
// stored one (redaction.MatchStoredProjection), so a replay never sends
// another record under the stored id. The producer emits no metric for it.
// It implies WithExportAfterLocalWrite with makeDurable: the row a stopped
// process committed may not be on disk yet.
func WithStoredReplay(ctx context.Context, stored []byte, makeDurable func(context.Context) error) context.Context {
	return context.WithValue(WithExportAfterLocalWrite(ctx, makeDurable), storedReplayKey{}, append([]byte(nil), stored...))
}

// StoredReplay reports whether ctx carries WithStoredReplay.
func StoredReplay(ctx context.Context) bool {
	_, marked := StoredReplayRecord(ctx)
	return marked
}

// StoredReplayRecord returns the stored projected record of a
// WithStoredReplay offer.
func StoredReplayRecord(ctx context.Context) ([]byte, bool) {
	if ctx == nil {
		return nil, false
	}
	stored, marked := ctx.Value(storedReplayKey{}).([]byte)
	return append([]byte(nil), stored...), marked
}
