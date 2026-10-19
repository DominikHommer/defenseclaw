// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookpriority gives a Windows hook process the CPU it needs to
// answer a tool call within its answer budget. defenseclaw-hook imports it
// for its init, which runs before the heavy package initialization of the
// CLI. It does nothing on Linux and macOS, where an account cannot raise its
// own priority; there the lifecycle runs at nice 10 instead.
package hookpriority
