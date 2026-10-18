# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build-helper regressions; these tests never invoke Cargo or a probe."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

_SPEC = importlib.util.spec_from_file_location(
    "windows_psec_prepare_build", Path(__file__).with_name("prepare_build.py")
)
assert _SPEC is not None and _SPEC.loader is not None
build = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(build)


class BuildGuardTests(TestCase):
    def test_source_identity_must_match_exact_commit(self) -> None:
        with (
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_dir", return_value=True),
            mock.patch.object(build, "command", return_value="other-commit") as command,
            self.assertRaisesRegex(RuntimeError, "reviewed commit"),
        ):
            build.verify_source("axis-source", build.AXIS_COMMIT)
        self.assertEqual(command.call_args.args[0], ["git", "rev-parse", "HEAD"])

    def test_dirty_pinned_source_refused_before_patch(self) -> None:
        with (
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_dir", return_value=True),
            mock.patch.object(build, "command", side_effect=[build.MXC_COMMIT, " M src/policy.rs"]),
            self.assertRaisesRegex(RuntimeError, "must be clean"),
        ):
            build.verify_source("mxc-source", build.MXC_COMMIT)

    def test_locked_build_without_lock_stops_before_source_or_tool_execution(self) -> None:
        with (
            mock.patch.object(build.sys, "argv", ["prepare_build.py", "build-locked"]),
            mock.patch.object(build.sys, "platform", "win32"),
            mock.patch.object(build.platform, "machine", return_value="AMD64"),
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(Path, "is_file", return_value=False),
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(build, "command") as command,
            self.assertRaisesRegex(RuntimeError, "reviewed combined Cargo.lock"),
        ):
            build.main()
        command.assert_not_called()

    def test_build_commands_do_not_inherit_credentials_or_rust_overrides(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {
                    "PATH": "/safe/bin",
                    "HOME": "/build",
                    "ANTHROPIC_API_KEY": "synthetic",
                    "LD_PRELOAD": "/synthetic",
                    "RUSTFLAGS": "synthetic",
                },
                clear=True,
            ),
            mock.patch.object(build.subprocess, "run", return_value=SimpleNamespace(stdout="identity\n")) as run,
        ):
            self.assertEqual(build.command(["git", "rev-parse", "HEAD"], capture=True), "identity")
        arguments = run.call_args.kwargs
        self.assertFalse(arguments["shell"])
        self.assertTrue(arguments["check"])
        self.assertLessEqual(arguments["timeout"], 2400)
        self.assertEqual(arguments["env"]["PATH"], "/safe/bin")
        self.assertNotIn("ANTHROPIC_API_KEY", arguments["env"])
        self.assertNotIn("LD_PRELOAD", arguments["env"])
        self.assertNotIn("RUSTFLAGS", arguments["env"])

    def test_generate_lock_refuses_broken_lock_symlink_before_tool_execution(self) -> None:
        def is_link(path: Path) -> bool:
            return path.name == "Cargo.lock"

        with (
            mock.patch.object(build.sys, "argv", ["prepare_build.py", "generate-lock"]),
            mock.patch.object(build.sys, "platform", "win32"),
            mock.patch.object(build.platform, "machine", return_value="AMD64"),
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(Path, "is_symlink", is_link),
            mock.patch.object(build, "command") as command,
            self.assertRaisesRegex(RuntimeError, "without Cargo.lock"),
        ):
            build.main()
        command.assert_not_called()

    def test_extra_source_change_is_refused(self) -> None:
        axis = Path("axis")
        mxc = Path("mxc")
        with (
            mock.patch.object(build, "command", side_effect=[build.AXIS_COMMIT, "?? extra.rs"]),
            self.assertRaisesRegex(RuntimeError, "four reviewed MXC overlay paths"),
        ):
            build.verify_build_sources(axis, mxc)

    def test_staged_source_change_is_refused(self) -> None:
        axis = Path("axis")
        mxc = Path("mxc")
        with (
            mock.patch.object(build, "command", side_effect=[build.AXIS_COMMIT, "", "src/staged.rs"]),
            self.assertRaisesRegex(RuntimeError, "staging is not permitted"),
        ):
            build.verify_build_sources(axis, mxc)

    def test_only_exact_four_unstaged_overlay_paths_are_accepted(self) -> None:
        axis = Path("axis")
        mxc = Path("mxc")
        status = "\n".join(f" M {path}" for path in sorted(build.PATCHED_PATHS))
        with mock.patch.object(build, "command", side_effect=[build.AXIS_COMMIT, "", "", build.MXC_COMMIT, status, ""]):
            build.verify_build_sources(axis, mxc)
