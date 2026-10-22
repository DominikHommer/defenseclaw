// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Recover a damaged counter only when the administrator supplied the exact
// installed config. The live gateway provides a counter that must not be
// lost when the service stops. Both lifecycle and config locks protect the
// repair; a changed file or unproven counter is refused before any write.
func repairWindowsEnterpriseConfigGeneration(ctx context.Context, opts *windowsEnterpriseLifecycleOptions, status *windowsEnterpriseInstallerReport) (bool, error) {
	if !status.Installed || status.TransactionPending || opts.configPath == "" ||
		!windowsEnterpriseIsElevated() || compareWindowsEnterpriseVersions(opts.productVersion, status.InstalledVersion) < 0 {
		return false, nil
	}
	approved, err := readWindowsEnterpriseBoundedFile(opts.configPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return false, nil
	} // The ordinary source preflight reports it.
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return false, err
	}
	installed, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil || !bytes.Equal(approved, installed) {
		return false, nil
	}
	attribution, _, err := managedStandaloneBundleGeneration(layout.ConfigPath, installed)
	if err != nil {
		return false, err
	}
	state, stateErr := configwrite.ReadGenerationState(layout.ConfigPath)
	if stateErr == nil && managedStandaloneGenerationMatches(state, installed, attribution) {
		return false, nil
	}
	// Releases before generation tracking may legitimately have no record.
	if errors.Is(stateErr, os.ErrNotExist) && compareWindowsEnterpriseVersions(opts.productVersion, status.InstalledVersion) > 0 {
		return false, nil
	}
	if err := windowsEnterpriseStandaloneConfigSource(opts.configPath); err != nil {
		return false, err
	}
	out, _ := windowsEnterprisePolicyDigest(ctx)
	var report policyDigestReport
	_ = json.Unmarshal(out, &report)
	floor := max(state.Generation, attribution.GenerationFloor)
	if report.GatewayReportedDigest != "" {
		floor = max(floor, report.GatewayReportedConfigGeneration)
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return false, err
	}
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		return false, fmt.Errorf("lifecycle_busy: cannot take lifecycle.lock to recover config generation; retry ensure after the current lifecycle finishes: %w", err)
	}
	defer release()
	pins := setTemporaryEnvironment(windowsEnterpriseServicePins(layout))
	defer pins()
	return repairManagedStandaloneConfigGeneration(ctx, layout.ConfigPath, approved, floor)
}
