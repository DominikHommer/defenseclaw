// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ValidateManagedStandaloneRuntimeCandidate runs the managed gateway's
// service-time content and path checks on a staged standalone config. The
// caller checks the staged file's ownership and the fixed layout separately.
// Before a first install the runtime directory does not yet exist; Setup
// creates it with its protected ACL before the strict installed-file load.
func ValidateManagedStandaloneRuntimeCandidate(cfg *Config) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return errors.New("standalone runtime candidate is unavailable")
	}
	return validateManagedEnterpriseRuntime(cfg, true, true)
}

func validateManagedEnterpriseRuntime(cfg *Config, checkPolicyInputs, allowAbsentDataDir bool) error {
	checkDataDir := true
	if allowAbsentDataDir {
		if _, err := os.Lstat(cfg.DataDir); errors.Is(err, os.ErrNotExist) {
			checkDataDir = false
		} else if err != nil {
			return fmt.Errorf("config: inspect managed data_dir: %w", err)
		}
	}
	if checkDataDir {
		if err := managed.ValidateTrustedServiceRuntimeDir(
			cfg.DataDir, "managed data_dir", os.Getenv(managed.WindowsServiceAccountEnv),
		); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_data_dir_untrusted")
			}
			return fmt.Errorf("config: managed_enterprise data_dir trust check failed: %w", err)
		}
	}
	if err := validateManagedEnterpriseListenerBindings(cfg); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "managed_listener_non_loopback")
		}
		return err
	}
	if checkPolicyInputs {
		if err := validateManagedStandalonePolicyInputs(cfg); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_policy_input_untrusted")
			}
			return err
		}
	}
	if err := validateManagedEnterpriseWindowsPeerAuthKnobs(cfg); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "managed_ipc_peer_auth_unsupported_on_windows")
		}
		return err
	}
	return nil
}
