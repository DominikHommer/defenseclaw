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

//go:build windows

package cli

import (
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// recordWindowsChange writes one change event into
// <ConfigDir>\bundles\change-events with the bundle version descriptors:
// SYSTEM and Administrators full control, the gateway service read, no
// standard user. Only an elevated caller records; the command's result
// stays the authoritative answer, so callers ignore a failure.
func recordWindowsChange(ev enterprisestatus.ChangeEvent) error {
	if !windowsSecretIsElevated() {
		return errors.New("only an elevated administrator records a change event")
	}
	layout, err := windowsBundleLayout()
	if err != nil {
		return err
	}
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
	return enterprisestatus.ChangeSpool{
		Dir: enterprisestatus.ChangeEventsDir(layout.ConfigDir),
		Prepare: func(dir string) error {
			return createWindowsBundleDirectory(dir, windowsBundleVersionSDDL(service.String(), true))
		},
		Publish: func(path string) error {
			return applyWindowsBundleSDDL(path, windowsBundleVersionSDDL(service.String(), false))
		},
	}.Write(ev)
}

// recordWindowsAnchorsChange records an anchor file a run installed.
func recordWindowsAnchorsChange(change *anchorOnlyChange) {
	if change == nil {
		return
	}
	previous := change.previous
	if !change.existed {
		previous = nil
	}
	if ev, ok := anchorsChangeEvent(previous, change.installed); ok {
		_ = recordWindowsChange(ev)
	}
}

// recordWindowsAnchorsFailure records a refused or failed anchor install;
// installed is the file still installed (nil: none).
func recordWindowsAnchorsFailure(code string, failed bool, installed []byte) {
	if ev, ok := anchorsFailureEvent(code, failed, installed); ok {
		_ = recordWindowsChange(ev)
	}
}
