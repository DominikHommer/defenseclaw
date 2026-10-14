// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The per-account cleanup appends one warning per image Docker could not
// remove. Both CLI formats must keep every warning and its administrator
// command; neither can hide all but the first leftover tag.
func TestEnterpriseUninstallRendersEveryLeftoverSandboxImage(t *testing.T) {
	r := enterprisestatus.New("uninstall", "standalone", "linux", "1.0.2")
	for _, tag := range []string{"defenseclaw/sandbox:sample-one", "defenseclaw/sandbox:sample-two"} {
		r.AddWarning("sandbox_user_state", "left DefenseClaw sandbox image "+tag+
			" (a1b2c3d4e5f6) of user sample-user: image is being used by a container; as root run `docker image rm "+tag+"`")
	}
	r.Finish("linux", 0)
	for _, asJSON := range []bool{false, true} {
		var out bytes.Buffer
		if err := printLifecycleResult(&out, r, asJSON); err != nil {
			t.Fatal(err)
		}
		for _, tag := range []string{"defenseclaw/sandbox:sample-one", "defenseclaw/sandbox:sample-two"} {
			if strings.Count(out.String(), tag) != 2 || !strings.Contains(out.String(), "docker image rm "+tag) {
				t.Errorf("json=%v output lost the warning or command for %s: %s", asJSON, tag, out.String())
			}
		}
		if !asJSON && !strings.Contains(out.String(), "done with 2 warnings") {
			t.Errorf("text output did not count both warnings: %s", out.String())
		}
	}
}
