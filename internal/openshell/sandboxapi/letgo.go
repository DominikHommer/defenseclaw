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

package sandboxapi

import "context"

// QueryLetGo, set to "1" on a stop, marks the user's own stop (`defenseclaw
// sandbox stop NAME`, Client.StopLetGo): one that finds a MicroVM which
// OpenShell does not stop (its workload completed, or it is in OpenShell's
// error state) lets it go, so that what stops the OpenShell gateway no
// longer waits for it (Sandbox.StopAskedIn). The stops DefenseClaw makes
// on its own, and those of a session or a pull, let none go. A daemon
// before DefenseClaw 1.0.4 ignores it.
const QueryLetGo = "let_go"

type letGoKey struct{}

// WithLetGo marks ctx as the user's own stop (QueryLetGo).
func WithLetGo(ctx context.Context) context.Context {
	return context.WithValue(ctx, letGoKey{}, true)
}

// LetGoFrom reports whether ctx is the user's own stop (WithLetGo).
func LetGoFrom(ctx context.Context) bool {
	v, _ := ctx.Value(letGoKey{}).(bool)
	return v
}
