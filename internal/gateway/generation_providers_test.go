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
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// GAP-0361 (#1099): a config_version 9 config written by 1.0.1 or 1.0.2
// whose llm_providers.custom entry is named like a built-in provider keeps
// every field it sets in the generation's provider registry. The lists are
// unioned with the built-in's, the maps take the entry's keys and every
// other field the entry sets wins. The registry dropped extra_headers.
func TestGenerationProvidersKeepEverySameNameCustomField(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", filepath.Join(dir, "custom-providers.json"))
	ca := filepath.Join(dir, "provider-ca", "openai.pem")
	if err := os.MkdirAll(filepath.Dir(ca), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, []byte("test certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`config_version: 9
data_dir: ` + dir + `
llm_providers:
  custom:
  - name: OpenAI
    domains: [llm.team.internal]
    profile_id: team
    env_keys: [TEAM_OPENAI_KEY]
    base_provider_type: openai
    base_url: https://llm.team.internal/v1
    allowed_requests: [chat, responses]
    available_models: [team-small]
    request_path_overrides: {chat: /team/chat}
    tls: {ca_cert_file: ` + ca + `}
    bedrock: {region: us-east-1, auth_mode: iam, access_key_env: AK, secret_key_env: SK, session_token_env: ST, profile_name: lab, inference_profile: us, deployment_aliases: {small: model-small}}
    vertex: {project_id: lab-project, region: us-central1, auth_mode: adc, service_account_json_env: SA_JSON}
    azure: {endpoint: https://team.openai.azure.example, api_version: 2026-01-01, auth_mode: api_key, deployment_aliases: {gpt: team-gpt}}
    extra_headers: {X-Team: sec, llm-model: team-small}
observability: {}
`)
	cfg, err := config.LoadRuntimeV8FromBytes(filepath.Join(dir, "config.yaml"), raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LLMProviders.Custom) != 1 {
		t.Fatalf("llm_providers.custom = %+v", cfg.LLMProviders.Custom)
	}
	custom := cfg.LLMProviders.Custom[0]
	// Read-back of the config itself, field by field.
	wantCustom := config.LLMCustomProvider{
		Name: "OpenAI", Domains: []string{"llm.team.internal"}, ProfileID: "team", EnvKeys: []string{"TEAM_OPENAI_KEY"},
		BaseProviderType: "openai", BaseURL: "https://llm.team.internal/v1",
		AllowedRequests: []string{"chat", "responses"}, AvailableModels: []string{"team-small"},
		RequestPathOverrides: map[string]string{"chat": "/team/chat"},
		TLS:                  &config.LLMCustomProviderTLS{CACertFile: ca},
		Bedrock: &config.BedrockKeyConfig{Region: "us-east-1", AuthMode: "iam", AccessKeyEnv: "AK", SecretKeyEnv: "SK",
			SessionTokenEnv: "ST", ProfileName: "lab", InferenceProfile: "us", DeploymentAliases: map[string]string{"small": "model-small"}},
		Vertex: &config.VertexKeyConfig{ProjectID: "lab-project", Region: "us-central1", AuthMode: "adc", ServiceAccountJSONEnv: "SA_JSON"},
		Azure: &config.AzureKeyConfig{Endpoint: "https://team.openai.azure.example", APIVersion: "2026-01-01", AuthMode: "api_key",
			DeploymentAliases: map[string]string{"gpt": "team-gpt"}},
		ExtraHeaders: map[string]string{"X-Team": "sec", "llm-model": "team-small"},
	}
	if !reflect.DeepEqual(custom, wantCustom) {
		t.Fatalf("llm_providers.custom[0] =\n  %+v\nwant\n  %+v", custom, wantCustom)
	}

	builtins, err := configs.LoadEmbeddedProviders()
	if err != nil {
		t.Fatal(err)
	}
	idx := slices.IndexFunc(builtins.Providers, func(p configs.Provider) bool { return p.Name == "openai" })
	if idx < 0 {
		t.Fatal("the embedded registry has no openai provider")
	}
	builtin := builtins.Providers[idx]

	got, err := buildGenerationProviders(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var merged []configs.Provider
	for _, p := range got.Providers {
		if p.Name == "openai" || p.Name == "OpenAI" {
			merged = append(merged, p)
		}
	}
	if len(merged) != 1 {
		t.Fatalf("registry has %d openai entries, want one merged entry: %+v", len(merged), merged)
	}
	entry := merged[0]
	profile := "team"
	want := builtin
	want.Domains = append(slices.Clone(builtin.Domains), "llm.team.internal")
	want.EnvKeys = append(slices.Clone(builtin.EnvKeys), "TEAM_OPENAI_KEY")
	want.ProfileID = &profile
	want.BaseProviderType, want.BaseURL = "openai", "https://llm.team.internal/v1"
	want.AllowedRequests = append(slices.Clone(builtin.AllowedRequests), "chat", "responses")
	want.AvailableModels = append(slices.Clone(builtin.AvailableModels), "team-small")
	want.RequestPathOverrides = map[string]string{"chat": "/team/chat"}
	for k, v := range builtin.RequestPathOverrides {
		if k != "chat" {
			want.RequestPathOverrides[k] = v
		}
	}
	want.ExtraHeaders = map[string]string{"X-Team": "sec", "llm-model": "team-small"}
	for k, v := range builtin.ExtraHeaders {
		if _, set := want.ExtraHeaders[k]; !set {
			want.ExtraHeaders[k] = v
		}
	}
	want.TLS = &configs.ProviderTLS{CACertPEM: "test certificate\n"}
	want.Bedrock = &configs.ProviderBedrock{Region: "us-east-1", AuthMode: "iam", AccessKeyEnv: "AK", SecretKeyEnv: "SK",
		SessionTokenEnv: "ST", ProfileName: "lab", InferenceProfile: "us", DeploymentAliases: map[string]string{"small": "model-small"}}
	want.Vertex = &configs.ProviderVertex{ProjectID: "lab-project", Region: "us-central1", AuthMode: "adc", ServiceAccountJSONEnv: "SA_JSON"}
	want.Azure = &configs.ProviderAzure{Endpoint: "https://team.openai.azure.example", APIVersion: "2026-01-01", AuthMode: "api_key",
		DeploymentAliases: map[string]string{"gpt": "team-gpt"}}
	if !reflect.DeepEqual(entry, want) {
		t.Fatalf("registry openai entry =\n  %+v\nwant\n  %+v", entry, want)
	}
	// Every provider field llm_providers can hold reaches the registry: a
	// field added to configs.Provider but not carried is caught here.
	value := reflect.ValueOf(entry)
	for i := 0; i < value.NumField(); i++ {
		name := value.Type().Field(i).Name
		if name == "RequestOverrides" { // a legacy overlay only; llm_providers can not hold it
			continue
		}
		if value.Field(i).IsZero() {
			t.Errorf("registry openai entry lost %s", name)
		}
	}
}
