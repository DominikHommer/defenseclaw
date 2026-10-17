// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A missing destination secret used to send start to the default port of the
// fallback configuration, which then blamed whoever held that port.
func TestMissingObservabilitySecretErrorNamesTheVariable(t *testing.T) {
	loadErr := fmt.Errorf("compile: %w", &config.V8SecretReferenceError{
		Destination: "galileo",
		Path:        `observability.destinations[1].headers["Galileo-API-Key"]`,
		Reference:   "GALILEO_API_KEY",
	})
	err := missingObservabilitySecretError("start", loadErr)
	if err == nil {
		t.Fatal("expected a refusal for a missing destination secret")
	}
	for _, want := range []string{
		`destination "galileo" needs GALILEO_API_KEY`,
		"defenseclaw keys set GALILEO_API_KEY",
		"defenseclaw-gateway start",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "--api-port") {
		t.Errorf("error %q still points at the port", err)
	}
	for _, other := range []error{nil, errors.New("config file is missing")} {
		if got := missingObservabilitySecretError("start", other); got != nil {
			t.Errorf("missingObservabilitySecretError(%v) = %v, want nil", other, got)
		}
	}
}

func TestShutdownConfigLoadsListenerWhenDestinationSecretIsUnset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const source = `config_version: 9
gateway:
  api_bind: 127.0.0.1
  api_port: 18987
observability:
  destinations:
    - name: archive
      kind: splunk_hec
      endpoint: https://collector.example.test/services/collector/event
      token_env: DC_SHUTDOWN_TEST_UNSET
`
	t.Setenv("DC_SHUTDOWN_TEST_UNSET", "")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadShutdownConfigWithoutDestinations(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Gateway.APIPort != 18987 || got.Gateway.APIBind != "127.0.0.1" {
		t.Fatalf("shutdown listener = %s:%d", got.Gateway.APIBind, got.Gateway.APIPort)
	}
}
