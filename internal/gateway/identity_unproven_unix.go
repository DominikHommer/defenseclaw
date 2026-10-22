// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

// forgetUnprovenFacts drops key's candidate facts (unprovenFacts): its last
// lookup ended another way, or the uid changed hands.
func forgetUnprovenFacts(key string) {
	unprovenFacts.Lock()
	defer unprovenFacts.Unlock()
	delete(unprovenFacts.entries, key)
}
