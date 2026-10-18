# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Codex user, machine-policy and legacy managed-user bindings by OS."""

import re

from scripts.connector_delta.platform_bindings import binding, function, machine_paths
from scripts.connector_delta.provider import _mask_go


def profiles(provider, common):
    paths, path_refs = machine_paths(provider, "CodexRequirementsPath", "programData")
    command, command_ref = function(
        provider,
        "registration",
        "codexHookCommandForPlatform",
        'goos == "windows"',
        "return windowsCodexHookCommandForEvent(event, contractID)",
        "return posixHookCommandWord(hookCommand)",
    )
    powershell, powershell_ref = function(
        provider,
        "helpers",
        "windowsNativePowerShellHookCommandForBoundEvent",
        "windowsAwaitedHookStatements(",
        "windowsSystemPowerShellExe()",
        "-EncodedCommand",
    )
    machine_command, machine_command_ref = function(
        provider,
        "machine_policy",
        "codexHookCommandForEvent",
        'opts.goos() == "windows"',
        "connector.WindowsCodexStandaloneManagedHookCommand(",
        'shellQuote(opts.HookBinary) + " hook --connector codex --enterprise-managed --event "',
    )
    machine_bridge, machine_bridge_ref = function(
        provider,
        "managed_bridge",
        "WindowsCodexStandaloneManagedHookCommand",
        "windowsCodexBoundManagedHookCommand(hookBinary, event, hookContract)",
    )
    machine_launcher, machine_launcher_ref = function(
        provider,
        "managed_launcher",
        "windowsCodexBoundManagedHookCommand",
        "windowsAwaitedHookStatements(hookBinary, arguments)",
        "windowsSystemPowerShellExe()",
        "-EncodedCommand",
    )
    managed_key, key_ref = function(
        provider, "machine_policy", "codexManagedDirKey", 'return "windows_managed_dir"', 'return "managed_dir"'
    )
    policy, policy_ref = function(
        provider,
        "machine_policy",
        "renderCodex",
        'adminCfg["allow_managed_hooks_only"]',
        '"allow_managed_hooks_only = true"',
        "codexHookCommandForEvent(",
    )
    legacy_path, legacy_ref = function(
        provider,
        "registration",
        "codexManagedConfigPath",
        "filepath.Join(filepath.Dir(codexConfigPath()), codexManagedConfigLogicalName)",
    )
    legacy_route, route_ref = function(
        provider,
        "registration",
        "codexUsesManagedHookLayer",
        'return runtime.GOOS == "windows" && opts.ManagedEnterprise',
    )
    constant = re.search(
        r'^const codexManagedConfigLogicalName = "([^"/]+)"$',
        _mask_go(provider.sources["registration"][1], comments_only=True),
        re.MULTILINE,
    )
    constant_ref = provider._ref("registration", constant.span()) if constant else None
    result = {}
    for platform in ("linux", "macos", "windows"):
        launchers = ["powershell.exe"] if platform == "windows" else ["posix-shell"]
        launcher_refs = [command_ref, powershell_ref] if platform == "windows" else [command_ref]
        user = {
            "hook.discovery": binding(common, "hook.discovery", {}, common["hook.discovery"]["evidence"]),
            "hook.registration": binding(common, "hook.registration", {}, common["hook.registration"]["evidence"]),
            "hook.execution": binding(
                common,
                "hook.execution",
                {"launchers": launchers},
                launcher_refs,
                bool(command and (platform != "windows" or powershell)),
            ),
        }
        managed = {
            "hook.discovery": binding(
                common,
                "hook.discovery",
                {"paths": [paths[platform]] if platform in paths else []},
                path_refs,
                platform in paths,
                inherit=False,
            ),
            "hook.registration": binding(
                common,
                "hook.registration",
                {
                    "keys": [
                        "hooks",
                        "handler.type=command",
                        "allow_managed_hooks_only",
                        "windows_managed_dir" if platform == "windows" else "managed_dir",
                    ]
                },
                [policy_ref, key_ref],
                bool(policy and managed_key),
                inherit=False,
            ),
            "hook.execution": binding(
                common,
                "hook.execution",
                {"launchers": launchers},
                [machine_command_ref, machine_bridge_ref, machine_launcher_ref]
                if platform == "windows"
                else [machine_command_ref],
                bool(machine_command and (platform != "windows" or machine_bridge and machine_launcher)),
            ),
        }
        result[platform] = {"user": user, "managed": managed}
        if platform == "windows":
            user_paths = common["hook.discovery"]["values"].get("paths", [])
            legacy = [path.rsplit("/", 1)[0] + "/" + constant[1] for path in user_paths] if constant else []
            result[platform]["managed-legacy"] = {
                **user,
                "hook.discovery": binding(
                    common,
                    "hook.discovery",
                    {"paths": legacy},
                    [legacy_ref, route_ref, constant_ref],
                    bool(legacy and legacy_path and legacy_route),
                ),
            }
    return result
