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

type storedLocallyKey struct{}

// WithStoredLocally marks an offer of an occurrence whose producer keeps it
// in a durable spool under a stable id and offers it until every sink has
// it (a trust anchor or credential change event), when the local store
// already holds it under that id. The local store is one sink of the
// spooled occurrence: the pipeline writes nothing locally and hands back
// only the optional-destination projections, which the runtime sends to
// the destinations that do not have it yet (RemoteDelivery). The record is
// built from the spooled occurrence alone, so it is the record of every
// earlier offer. The producer records no metric for it: they were recorded
// with the row.
func WithStoredLocally(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, storedLocallyKey{}, true)
}

// StoredLocally reports whether ctx carries WithStoredLocally.
func StoredLocally(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	marked, _ := ctx.Value(storedLocallyKey{}).(bool)
	return marked
}
