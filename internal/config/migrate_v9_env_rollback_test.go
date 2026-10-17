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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
)

// GAP-0808 (#1099): when the config generation record can not be written,
// the 0.8.x migration reports a failure and puts config.yaml back; the
// inline scanner key it had moved to .env is taken back out too, so a
// failed run leaves nothing migrated. A retry then moves it once.
func TestMigrateV9FailedCommitTakesTheMovedKeyBackOutOfDotEnv(t *testing.T) {
	for name, previous := range map[string]*string{"no .env": nil, "an existing .env": ptr("OTHER_KEY=kept\n")} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("VIRUSTOTAL_API_KEY", "")
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			configPath := filepath.Join(dir, "config.yaml")
			source := "config_version: 8\ndata_dir: " + dir + "\nscanners:\n  skill_scanner:\n    use_virustotal: true\n" +
				"    virustotal_api_key: vt-test-value\nobservability: {}\n"
			if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			envPath := filepath.Join(dir, ".env")
			if previous != nil {
				if err := os.WriteFile(envPath, []byte(*previous), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// A directory where the generation record goes makes the commit fail.
			generation := cfgtxn.GenerationPath(configPath)
			if err := os.MkdirAll(filepath.Join(generation, "blocker"), 0o700); err != nil {
				t.Fatal(err)
			}

			result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
			if err == nil {
				t.Fatal("MigrateV9 succeeded with an unwritable generation record")
			}
			if raw, _ := os.ReadFile(configPath); string(raw) != source {
				t.Fatalf("config.yaml after the failed commit =\n%s", raw)
			}
			env, envErr := os.ReadFile(envPath)
			switch {
			case previous == nil && !errors.Is(envErr, fs.ErrNotExist):
				t.Fatalf(".env after the failed commit = %q (%v), want no file", env, envErr)
			case previous != nil && string(env) != *previous:
				t.Fatalf(".env after the failed commit = %q, want %q", env, *previous)
			}
			if result != nil && slices.Contains(result.Written, envPath) {
				t.Errorf("written lists %s after it was put back: %v", envPath, result.Written)
			}

			if err := os.RemoveAll(generation); err != nil {
				t.Fatal(err)
			}
			if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err != nil {
				t.Fatalf("retry: %v", err)
			}
			env, _ = os.ReadFile(envPath)
			if strings.Count(string(env), "VIRUSTOTAL_API_KEY=vt-test-value") != 1 ||
				(previous != nil && !strings.HasPrefix(string(env), *previous)) {
				t.Fatalf(".env after the retry = %q", env)
			}
		})
	}
}

func ptr(s string) *string { return &s }
