# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build-helper regressions; these tests never invoke Cargo or a probe."""

from __future__ import annotations

import importlib.util
import io
import os
import stat
import tempfile
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
    def test_probe_slice_accepts_only_the_two_reviewed_fixed_contracts(self) -> None:
        self.assertEqual(
            build.PROBE_SLICE_CONTRACTS,
            {
                "dll-startup-only": (
                    "standalone_std_fixed_dll_startup_diagnostic",
                    "fixed_windows_native_psec_dll_startup_diagnostic",
                ),
                "claude-version-only": (
                    "standalone_std_fixed_signed_claude_version",
                    "fixed_windows_native_psec_signed_claude_version",
                ),
            },
        )
        with (
            mock.patch.object(build.sys, "argv", ["prepare_build.py", "build-locked", "--probe-slice", "unreviewed"]),
            mock.patch.object(build.sys, "stderr", io.StringIO()),
            mock.patch.object(build, "command") as command,
            mock.patch.object(build, "verify_source") as source,
            self.assertRaises(SystemExit) as failure,
        ):
            build.main()
        self.assertEqual(failure.exception.code, 2)
        command.assert_not_called()
        source.assert_not_called()

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
            self.assertRaisesRegex(RuntimeError, "reviewed MXC overlay paths"),
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

    def test_only_exact_modified_and_added_overlay_paths_are_accepted(self) -> None:
        axis = Path("axis")
        mxc = Path("mxc")
        status = "\n".join(
            [f" M {path}" for path in sorted(build.PATCHED_PATHS)]
            + [f"?? {path}" for path in sorted(build.ADDED_PATHS)]
        )
        with mock.patch.object(build, "command", side_effect=[build.AXIS_COMMIT, "", "", build.MXC_COMMIT, status, ""]):
            build.verify_build_sources(axis, mxc)

    def test_missing_added_overlay_file_is_refused(self) -> None:
        status = "\n".join(f" M {path}" for path in sorted(build.PATCHED_PATHS))
        with (
            mock.patch.object(build, "command", side_effect=[build.AXIS_COMMIT, "", "", build.MXC_COMMIT, status]),
            self.assertRaisesRegex(RuntimeError, "reviewed MXC overlay paths"),
        ):
            build.verify_build_sources(Path("axis"), Path("mxc"))

    def test_fingerprints_detect_added_file_mutation_outside_git_diff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in build.PATCHED_PATHS | build.ADDED_PATHS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"fixed source\n")
            before = build.overlay_fingerprints(root)
            changed = sorted(build.ADDED_PATHS)[0]
            (root / changed).write_bytes(b"changed source\n")
            after = build.overlay_fingerprints(root)
            self.assertNotEqual(before[changed], after[changed])
            self.assertEqual(set(before), build.PATCHED_PATHS | build.ADDED_PATHS)

    def test_overlay_junction_is_refused_before_read(self) -> None:
        with (
            mock.patch.object(
                Path,
                "lstat",
                return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o600,
                    st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
                    st_size=42,
                ),
            ),
            mock.patch.object(build, "digest") as digest,
            self.assertRaisesRegex(RuntimeError, "bounded regular file"),
        ):
            build.overlay_fingerprints(Path("mxc"))
        digest.assert_not_called()

    def test_windows_overlay_requires_all_four_reviewed_paths(self) -> None:
        rows = ["1\t0\t" + path for path in sorted(build.WINDOWS_ARGV_PATCH_PATHS)]
        with mock.patch.object(build, "command", return_value="\n".join(rows)):
            build.verify_windows_patch_paths(Path("mxc"))
        for changed in [rows[:-1], rows + ["1\t0\tunreviewed.rs"], rows[:-1] + [rows[0]]]:
            with (
                self.subTest(rows=changed),
                mock.patch.object(build, "command", return_value="\n".join(changed)),
                self.assertRaisesRegex(RuntimeError, "four reviewed source paths"),
            ):
                build.verify_windows_patch_paths(Path("mxc"))

    def test_native_identity_overlay_cannot_add_an_unreviewed_sdk_path(self) -> None:
        rows = ["1\t0\t" + path for path in sorted(build.IDENTITY_PATCH_PATHS)]
        with mock.patch.object(build, "command", return_value="\n".join(rows)):
            build.verify_identity_patch_paths(Path("mxc"))
        for changed in [rows[:-1], rows + ["1\t0\tunreviewed.rs"], rows[:-1] + [rows[0]]]:
            with (
                self.subTest(rows=changed),
                mock.patch.object(build, "command", return_value="\n".join(changed)),
                self.assertRaisesRegex(RuntimeError, "four reviewed source paths"),
            ):
                build.verify_identity_patch_paths(Path("mxc"))
