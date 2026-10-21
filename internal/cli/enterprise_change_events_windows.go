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
	"fmt"
	"io"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsChangeSpool is the change spool <ConfigDir>\bundles\change-events
// with the bundle version descriptors: SYSTEM and Administrators full
// control, the gateway service read, no standard user. An event the gateway
// marked reported under <DataDir> may be removed. A test replaces it.
var windowsChangeSpool = func() (enterprisestatus.ChangeSpool, error) {
	layout, err := windowsBundleLayout()
	if err != nil {
		return enterprisestatus.ChangeSpool{}, err
	}
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return enterprisestatus.ChangeSpool{}, err
	}
	return enterprisestatus.ChangeSpool{
		Dir:      enterprisestatus.ChangeEventsDir(layout.ConfigDir),
		Reported: func(id string) bool { return enterprisestatus.ChangeReported(layout.DataDir, id) },
		Prepare: func(dir string) error {
			return createWindowsBundleDirectory(dir, windowsBundleVersionSDDL(service.String(), true))
		},
		Publish: func(path string) error {
			return applyWindowsBundleSDDL(path, windowsBundleVersionSDDL(service.String(), false))
		},
	}, nil
}

// recordWindowsChange writes one change event. Only an elevated caller
// records; any other records nothing and reports no error. A command calls
// windowsChangeSpoolReady before it changes anything and reports a failure
// here as change_unrecorded.
func recordWindowsChange(ev enterprisestatus.ChangeEvent) error {
	if !windowsSecretIsElevated() {
		return nil
	}
	spool, err := windowsChangeSpool()
	if err != nil {
		return err
	}
	return spool.Write(ev)
}

// windowsChangeSpoolReady checks that the change spool can take the event
// of a change about to be made (enterprisestatus.ChangeSpool.Ready).
func windowsChangeSpoolReady() error {
	if !windowsSecretIsElevated() {
		return nil
	}
	spool, err := windowsChangeSpool()
	if err != nil {
		return err
	}
	return spool.Ready()
}

// recordWindowsAnchorsChange records an anchor file a run installed.
func recordWindowsAnchorsChange(change *anchorOnlyChange) error {
	if change == nil {
		return nil
	}
	previous := change.previous
	if !change.existed {
		previous = nil
	}
	if ev, ok := anchorsChangeEvent(previous, change.installed); ok {
		return recordWindowsChange(ev)
	}
	return nil
}

// recordWindowsAnchorsFailure records a refused or failed anchor install;
// installed is the file still installed (nil: none).
func recordWindowsAnchorsFailure(code string, failed bool, installed []byte) error {
	if ev, ok := anchorsFailureEvent(code, failed, installed); ok {
		return recordWindowsChange(ev)
	}
	return nil
}

// warnChangeUnrecorded prints change_unrecorded on w for a run whose result
// document has no warnings to carry it.
func warnChangeUnrecorded(w io.Writer, err error) {
	if err == nil || w == nil {
		return
	}
	warning := changeUnrecordedWarning(err)
	fmt.Fprintf(w, "warning: %s: %s\n", warning.Code, warning.Message)
}
