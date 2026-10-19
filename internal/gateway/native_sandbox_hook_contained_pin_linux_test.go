// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64 && axis_native_contained_hook_canary

package gateway

// Closed in checked-in source. The reviewed build-only recipe replaces this
// exact literal with the just-built payload's SHA, then compiles and retains
// both generated source and images for independent inert review. Runtime flags,
// environment, request labels and receipts cannot choose the admitted image.
const containedPayloadSHA = ""
