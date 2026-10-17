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

package harness

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// #1296: in an image with trusted CAs, Node and Deno read OpenShell's
// combined bundle (which holds them) instead of OpenShell's own CA alone,
// in every harness launcher, login shell and `sandbox exec` command; an
// image without trusted CAs keeps OpenShell's variables.
func TestSandboxShellsPointNodeAtTheTrustedCAs(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	for _, name := range Names() {
		spec, _ := Get(name)
		if !strings.Contains(string(spec.Launcher().Data), trustedCAScript) {
			t.Errorf("the %s launcher does not run the trusted CA script", name)
		}
	}
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca-certificates", "defenseclaw")
	bundle := filepath.Join(dir, "ca-bundle.crt")
	if err := os.WriteFile(bundle, []byte("bundle\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		// The in-image directory, moved into the test's own.
		if err := os.WriteFile(p, []byte(strings.ReplaceAll(string(data), openshell.SandboxTrustedCADir, caDir)), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	profile := write("profile.sh", shellFile(t, Copilot, SandboxProfilePath).Data, 0o644)
	wrapper := write("sandbox-env", shellFile(t, Copilot, SandboxEnvPath).Data, 0o755)
	const record = `printf 'NODE_EXTRA_CA_CERTS=%s\nDENO_CERT=%s\n' "${NODE_EXTRA_CA_CERTS-<unset>}" "${DENO_CERT-<unset>}"`
	run := func(env []string) map[string]map[string]string {
		env = append([]string{"PATH=/usr/bin:/bin"}, env...)
		login := exec.Command("/bin/sh", "-c", ". "+profile+"\n"+record)
		login.Env = env
		wrapped := exec.Command(wrapper, "/bin/sh", "-c", record)
		wrapped.Env = env
		out := map[string]map[string]string{}
		for what, cmd := range map[string]*exec.Cmd{"login shell": login, "sandbox exec": wrapped} {
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", what, err, b)
			}
			out[what] = shellEnvLines(string(b))
		}
		return out
	}
	openShellEnv := []string{"SSL_CERT_FILE=" + bundle, "NODE_EXTRA_CA_CERTS=/run/openshell-ca.crt", "DENO_CERT=/run/openshell-ca.crt"}
	for what, got := range run(openShellEnv) {
		if got["NODE_EXTRA_CA_CERTS"] != "/run/openshell-ca.crt" || got["DENO_CERT"] != "/run/openshell-ca.crt" {
			t.Errorf("%s without trusted CAs changed the CA variables: %v", what, got)
		}
	}
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for what, got := range run(openShellEnv) {
		if got["NODE_EXTRA_CA_CERTS"] != bundle || got["DENO_CERT"] != bundle {
			t.Errorf("%s with trusted CAs: %v, want the combined bundle %s", what, got, bundle)
		}
	}
	// A bundle that is not there leaves OpenShell's variables alone.
	for what, got := range run([]string{"SSL_CERT_FILE=" + bundle + ".gone", "NODE_EXTRA_CA_CERTS=/run/openshell-ca.crt"}) {
		if got["NODE_EXTRA_CA_CERTS"] != "/run/openshell-ca.crt" {
			t.Errorf("%s with a missing bundle: %v", what, got)
		}
	}
}
