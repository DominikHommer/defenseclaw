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

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// GAP-0163: folding a legacy custom-providers.json into a config_version 9
// config.yaml keeps the provider registry the gateway built from both files:
// the same domains, keys, path overrides and headers for the same-name
// provider, the overlay's new provider and its Ollama port.
func TestFoldedLegacyOverlayKeepsTheGenerationRegistry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_HOME", dir)
	overlayPath := filepath.Join(dir, "custom-providers.json")
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", overlayPath)
	configPath := filepath.Join(dir, "config.yaml")
	raw := `config_version: 9
data_dir: ` + dir + `
llm_providers:
  custom:
    - name: acme-gw
      domains: [b11-acme.example.test]
      profile_id: b11-acme-profile
      env_keys: [B11_ACME_DUMMY_KEY]
      base_provider_type: openai
      base_url: https://b11-acme.example.test/v1
      request_path_overrides: {chat: /acme/chat, responses: /acme/responses}
      extra_headers: {X-B11-Config: dummy-config}
observability: {}
`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := `{"providers":[
  {"name":"ACME-GW","domains":["b11-acme-alt.example.test"],"env_keys":["B11_ACME_LEGACY_DUMMY_KEY"],
   "request_path_overrides":{"legacy":"/legacy/only"},"extra_headers":{"X-B11-Legacy":"dummy-legacy"}},
  {"name":"b11-new","domains":["b11-new.example.test"],"env_keys":["B11_NEW_KEY"]}
 ],"ollama_ports":[11500]}`
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := func(stage string) *generationProviders {
		t.Helper()
		cfg, err := config.LoadRuntimeV8File(configPath)
		if err != nil {
			t.Fatalf("%s: load: %v", stage, err)
		}
		reg, err := buildGenerationProviders(cfg)
		if err != nil {
			t.Fatalf("%s: build: %v", stage, err)
		}
		return reg
	}
	before := registry("before")
	result, err := config.MigrateV9(context.Background(), config.MigrateV9Input{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if result.ProvidersFold == nil || result.ProvidersFold.Retired == "" {
		t.Fatalf("ProvidersFold = %+v, want the overlay folded and retired", result.ProvidersFold)
	}
	if _, err := os.Stat(overlayPath); !os.IsNotExist(err) {
		t.Fatalf("the overlay is still a live input: %v", err)
	}
	after := registry("after")

	find := func(reg *generationProviders, name string) configs.Provider {
		t.Helper()
		for _, p := range reg.Providers {
			if strings.EqualFold(p.Name, name) {
				p.Name = strings.ToLower(p.Name)
				p.Domains = slices.Sorted(slices.Values(p.Domains))
				p.EnvKeys = slices.Sorted(slices.Values(p.EnvKeys))
				return p
			}
		}
		t.Fatalf("the registry has no %s provider", name)
		return configs.Provider{}
	}
	for _, name := range []string{"acme-gw", "b11-new", "openai"} {
		if got, want := find(after, name), find(before, name); !reflect.DeepEqual(got, want) {
			t.Errorf("%s after the fold =\n  %+v\nbefore\n  %+v", name, got, want)
		}
	}
	acme := find(after, "acme-gw")
	if acme.ExtraHeaders["X-B11-Config"] != "dummy-config" || acme.ExtraHeaders["X-B11-Legacy"] != "dummy-legacy" ||
		acme.RequestPathOverrides["legacy"] != "/legacy/only" || acme.BaseURL != "https://b11-acme.example.test/v1" {
		t.Errorf("acme-gw = %+v", acme)
	}
	if got, want := slices.Sorted(slices.Values(after.OllamaPorts)), slices.Sorted(slices.Values(before.OllamaPorts)); !reflect.DeepEqual(got, want) {
		t.Errorf("ollama ports after %v, before %v", got, want)
	}
}
