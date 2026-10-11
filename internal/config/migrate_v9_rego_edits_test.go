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

package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/rego"
)

// GAP-1498: an operator who added a rule to the 0.8.x admission.rego (a
// block on a named skill) lost it when the upgrade replaced the module with
// the shipped one. The rule is carried to a custom module that reads the
// same value from input; an edit to the 0.8.x rules themselves is reported.
func TestMigrateV9KeepsRulesAddedToVendorRego(t *testing.T) {
	pristine, err := legacy08Rego.ReadFile("legacy08rego/admission-0.8.0.rego")
	if err != nil {
		t.Fatal(err)
	}
	const added = "\n_is_blocked if {\n\tinput.target_name == \"marker-skill\"\n\tdata.config.scan_on_install == true\n}\n"
	for _, tc := range []struct{ name, module string }{
		{"added rule", string(pristine) + added},
		{"changed rule", strings.Replace(string(pristine), "default verdict := \"scan\"", "default verdict := \"blocked\"", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			policies := filepath.Join(dir, "policies")
			regoDir := filepath.Join(policies, "rego")
			if err := os.MkdirAll(regoDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(regoDir, "admission.rego"), []byte(tc.module), 0o600); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte("config_version: 8\ndata_dir: "+dir+"\npolicy_dir: "+policies+
				"\nobservability: {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			policyDir, dataJSON := V8PolicyDataJSON(policies)
			result, err := MigrateV9(context.Background(), MigrateV9Input{
				ConfigPath: configPath, PolicyDir: policyDir, DataJSONPath: dataJSON,
			})
			if err != nil {
				t.Fatal(err)
			}
			carried := filepath.Join(regoDir, "custom-admission-from-0.8.rego")
			if tc.name == "changed rule" {
				lost := strings.Join(result.Record.UnenforcedRegoData, "\n")
				if _, err := os.Stat(carried); err == nil || len(result.Record.CarriedRegoRules) != 0 ||
					!strings.Contains(lost, "admission.rego was edited, but it changes or removes rules") {
					t.Fatalf("a changed 0.8.x rule was not reported: %q %q", lost, result.Record.CarriedRegoRules)
				}
				return
			}
			if len(result.Record.CarriedRegoRules) != 1 || len(result.Record.UnenforcedRegoData) != 0 {
				t.Fatalf("carried %q, unenforced %q", result.Record.CarriedRegoRules, result.Record.UnenforcedRegoData)
			}
			verdict := func(skill string) string {
				t.Helper()
				query, err := rego.New(rego.Query("data.defenseclaw.admission.verdict"),
					rego.Load([]string{regoDir}, func(abs string, info os.FileInfo, depth int) bool {
						return !info.IsDir() && filepath.Ext(abs) != ".rego"
					}),
					rego.Input(map[string]any{"target_type": "skill", "target_name": skill,
						"admission": map[string]any{"scan_on_install": true}}),
				).Eval(context.Background())
				if err != nil || len(query) != 1 {
					t.Fatalf("evaluate %s: %v %v", skill, query, err)
				}
				return query[0].Expressions[0].Value.(string)
			}
			if got := verdict("marker-skill"); got != "blocked" {
				t.Errorf("marker-skill verdict %q; want blocked by the carried rule", got)
			}
			if got := verdict("other-skill"); got == "blocked" {
				t.Errorf("other-skill verdict %q", got)
			}
		})
	}
}
