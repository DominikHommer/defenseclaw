# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Claude file-policy and launcher bindings, split by OS and deployment."""

import re

from scripts.connector_delta.platform_bindings import binding, function, machine_paths
from scripts.connector_delta.provider import _mask_go


def profiles(provider, common):
    roots, root_refs = machine_paths(provider, "ClaudeManagedDir", "programFiles")
    dropin, dropin_ref = function(
        provider,
        "machine_policy",
        "claudeDropInPath",
        'joinFor(opts, dir, "managed-settings.d")',
        "DefenseClawDropInName",
    )
    constants = _mask_go(provider.sources["machine_paths"][1], comments_only=True)
    name = re.search(r'^const DefenseClawDropInName = "([^"/]+)"$', constants, re.MULTILINE)
    name_ref = provider._ref("machine_paths", name.span()) if name else None
    handler, handler_ref = function(
        provider,
        "machine_policy",
        "claudeHandler",
        'handler.set("type", "command")',
        'opts.goos() == "windows"',
        'handler.set("command", opts.HookBinary)',
        'handler.set("args",',
        'shellQuote(opts.HookBinary)+" hook --connector claudecode --enterprise-managed"',
    )
    policy, policy_ref = function(
        provider,
        "machine_policy",
        "renderClaudeDropIn",
        'doc.set("allowManagedHooksOnly", true)',
        'doc.set("hooks", hooks)',
        "claudeHandler(opts, group)",
    )
    invocation, invocation_ref = function(
        provider,
        "registration",
        "claudeCodeHookInvocation",
        'runtime.GOOS == "windows"',
        "claudeCodeWindowsHookInvocation(opts, executable)",
        "posixHookCommandWord(hookCommand)",
    )
    windows, windows_ref = function(
        provider,
        "launcher",
        "claudeCodeWindowsHookInvocation",
        "!opts.ManagedEnterprise && claudeCodeLauncherGuardable(executable)",
        "return claudeCodeWindowsCommandProcessor(), claudeCodeLauncherGuardArgs(executable, args)",
        "return executable, args",
    )
    processor, processor_ref = function(
        provider, "launcher", "claudeCodeWindowsCommandProcessor", 'filepath.Join(root, "System32", "cmd.exe")'
    )
    result = {}
    for platform in ("linux", "macos", "windows"):
        launcher_refs = [invocation_ref, windows_ref, processor_ref] if platform == "windows" else [invocation_ref]
        user = {
            "hook.discovery": binding(common, "hook.discovery", {}, common["hook.discovery"]["evidence"]),
            "hook.registration": binding(common, "hook.registration", {}, common["hook.registration"]["evidence"]),
            "hook.execution": binding(
                common,
                "hook.execution",
                {"launchers": ["cmd.exe", "native-exec"] if platform == "windows" else ["posix-shell"]},
                launcher_refs,
                bool(invocation and (platform != "windows" or windows and processor)),
            ),
        }
        root = roots.get(platform)
        sep = "\\" if platform == "windows" else "/"
        directory = root + sep + "managed-settings.d" if root else None
        paths = [directory + sep + name[1], directory] if directory and name else []
        managed = {
            "hook.discovery": binding(
                common,
                "hook.discovery",
                {"paths": paths},
                [*root_refs, dropin_ref, name_ref],
                bool(paths and dropin),
                inherit=False,
            ),
            "hook.registration": binding(
                common,
                "hook.registration",
                {"keys": ["hooks", "handler.type=command", "allowManagedHooksOnly"]},
                [handler_ref, policy_ref],
                bool(handler and policy),
                inherit=False,
            ),
            "hook.execution": binding(
                common,
                "hook.execution",
                {"launchers": ["native-exec"] if platform == "windows" else ["posix-shell"]},
                [handler_ref],
                bool(handler),
            ),
        }
        result[platform] = {"user": user, "managed": managed}
    return result
