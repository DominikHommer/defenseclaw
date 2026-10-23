// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"path/filepath"
	"runtime"
	"strings"
)

// PluginLaunchCoverage reports a launch that can omit a managed in-agent
// plugin. It examines only the process's own argv and environment, never a
// prompt, and returns a fixed reason so neither can leak into a status or
// audit record. An unreadable environment is unknown, not proof of coverage.
func PluginLaunchCoverage(connector string, argv []string, env map[string]string, envKnown bool, accountHome string) string {
	switch connector {
	case "opencode":
		args := argv
		if len(args) != 0 {
			args = args[1:]
		}
		for _, arg := range args {
			if arg == "--" {
				break
			}
			if arg == "--pure" || arg == "--pure=true" || arg == "--pure=1" {
				return "opencode_pure"
			}
		}
		if !envKnown {
			return "launch_environment_unverified"
		}
		if env["OPENCODE_PURE"] != "" {
			return "opencode_pure"
		}
		if env["OPENCODE_TEST_MANAGED_CONFIG_DIR"] != "" {
			return "opencode_managed_config_relocated"
		}
		if env["OPENCODE_CONFIG_DIR"] != "" {
			return "opencode_user_config_relocated"
		}
		if accountHome == "" {
			return "launch_environment_unverified"
		}
		if launchHomeRelocated(env, accountHome) {
			return "opencode_user_config_relocated"
		}
		if xdg := env["XDG_CONFIG_HOME"]; xdg != "" && !sameLaunchPath(xdg, filepath.Join(accountHome, ".config")) {
			return "opencode_user_config_relocated"
		}
	case "amp":
		return userConfigLaunchCoverage(env, envKnown, accountHome, "amp_plugin_config_relocated")
	case "devin":
		for _, arg := range launchOptions(argv) {
			if arg == "--config" || strings.HasPrefix(arg, "--config=") {
				return "devin_config_override"
			}
		}
		if launchWindowsAppDataRelocated(env, accountHome, "APPDATA", "Roaming") {
			return "user_config_relocated"
		}
		return userConfigLaunchCoverage(env, envKnown, accountHome, "user_config_relocated")
	case "antigravity":
		return userConfigLaunchCoverage(env, envKnown, accountHome, "user_config_relocated")
	case "hermes":
		for _, arg := range launchOptions(argv) {
			if (len(arg) >= len("--sa") && strings.HasPrefix("--safe-mode", arg)) ||
				arg == "--safe-mode=true" || arg == "--safe-mode=1" {
				return "hermes_safe_mode"
			}
		}
		if !envKnown {
			return "launch_environment_unverified"
		}
		if env["HERMES_SAFE_MODE"] != "" {
			return "hermes_safe_mode"
		}
		if env["HERMES_MANAGED_DIR"] != "" || env["HERMES_HOME"] != "" &&
			(accountHome == "" || !sameLaunchPath(env["HERMES_HOME"], filepath.Join(accountHome, ".hermes"))) {
			return "hermes_config_relocated"
		}
		if launchWindowsAppDataRelocated(env, accountHome, "LOCALAPPDATA", "Local") {
			return "hermes_config_relocated"
		}
		return userConfigLaunchCoverage(env, envKnown, accountHome, "user_config_relocated")
	case "kiro":
		args := argv
		if len(args) != 0 {
			args = args[1:]
		}
		resume := false
		for index, arg := range args {
			if arg == "--" {
				break
			}
			if arg == "--cloud" {
				return "kiro_cloud_session"
			}
			if arg == "--resume-id" || strings.HasPrefix(arg, "--resume-id=") {
				resume = true
			}
			if arg == "--agent" && (index+1 >= len(args) || args[index+1] != "defenseclaw") {
				return "kiro_alternate_agent"
			}
			if selected, ok := strings.CutPrefix(arg, "--agent="); ok && selected != "defenseclaw" {
				return "kiro_alternate_agent"
			}
		}
		if resume {
			return "kiro_resume_placement_unverified"
		}
		if !envKnown {
			return "launch_environment_unverified"
		}
		if env["KIRO_HOME"] != "" || env["KIRO_AGENT_CONFIG_DIR"] != "" || env["KIRO_TEST_AGENTS_DIR"] != "" {
			return "kiro_hook_config_relocated"
		}
	}
	return ""
}

func sameLaunchPath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func launchHomeRelocated(env map[string]string, accountHome string) bool {
	keys := []string{"HOME"}
	if runtime.GOOS == "windows" {
		keys = append(keys, "USERPROFILE")
	}
	for _, key := range keys {
		if home := env[key]; home != "" && !sameLaunchPath(home, accountHome) {
			return true
		}
	}
	return false
}

func launchWindowsAppDataRelocated(env map[string]string, accountHome, key, leaf string) bool {
	value := env[key]
	return runtime.GOOS == "windows" && value != "" && accountHome != "" &&
		!sameLaunchPath(value, filepath.Join(accountHome, "AppData", leaf))
}

func launchOptions(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	for index, arg := range argv[1:] {
		if arg == "--" {
			return argv[1 : index+1]
		}
	}
	return argv[1:]
}

func userConfigLaunchCoverage(env map[string]string, envKnown bool, accountHome, relocatedReason string) string {
	profileKnown := runtime.GOOS == "windows" && env["USERPROFILE"] != ""
	if !envKnown || accountHome == "" || env["HOME"] == "" && !profileKnown && env["XDG_CONFIG_HOME"] == "" {
		return "launch_environment_unverified"
	}
	if launchHomeRelocated(env, accountHome) {
		return relocatedReason
	}
	if xdg := env["XDG_CONFIG_HOME"]; xdg != "" && !sameLaunchPath(xdg, filepath.Join(accountHome, ".config")) {
		return relocatedReason
	}
	return ""
}
