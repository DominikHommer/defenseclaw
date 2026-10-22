// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
)

// runIsolatedFromTheHostsHermes runs the package's tests off the host's
// Hermes setup (hermespath.IsolateHostForTests): a HERMES_HOME a Hermes
// developer exported failed the Hermes Setup and Verify tests.
func runIsolatedFromTheHostsHermes(m *testing.M) int {
	cleanup, err := hermespath.IsolateHostForTests()
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolate the tests from the host's Hermes:", err)
		return 1
	}
	defer cleanup()
	return m.Run()
}

// Run with HERMES_HOME exported, the tests still see none.
func TestConnectorTestsRunWithoutTheHostsHermesEnvironment(t *testing.T) {
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "HERMES_") {
			t.Fatalf("the tests run with the host's %s", variable)
		}
	}
}
