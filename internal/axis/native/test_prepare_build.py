# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Inert build-admission tests; no compiler, peer or sandbox is launched."""

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import prepare_build as build
import prepare_windows_build as windows_build


def lock(*, version="1.0.0", checksum="a" * 64, source=None, paths=None):
    source = source or "registry+https://github.com/rust-lang/crates.io-index"
    paths = build.PATH_PACKAGES if paths is None else paths
    parts = [
        f'version = 4\n\n[[package]]\nname = "safe"\nversion = "{version}"\n'
        f'source = "{source}"\nchecksum = "{checksum}"\n'
    ]
    for name, value in sorted(paths):
        parts.append(f'\n[[package]]\nname = "{name}"\nversion = "{value}"\n')
    return "".join(parts).encode()


class BuildAdmissionTests(unittest.TestCase):
    def test_windows_evidence_is_not_an_applied_linux_patch_or_native_test_input(self):
        self.assertTrue(build.WINDOWS_SOURCE <= build.SOURCE)
        self.assertFalse(build.WINDOWS_SOURCE & build.PATCHES.keys())
        names = {
            "src/linux.rs",
            "src/windows.rs",
            "src/windows_future.rs",
            "src/windows_conpty_diagnostic.rs",
            "src/bin/windows_conpty_diagnostic.rs",
        }

        def read(path):
            self.assertNotEqual(path.name, "windows.rs")
            return b"#[test]\nfn fixed() {}\n"

        with patch.object(build, "SOURCE", names), patch.object(build, "ordinary", side_effect=read) as source:
            self.assertEqual(build.native_test_inventory(), {"linux::tests::fixed", "windows_future::tests::fixed"})
            self.assertEqual(source.call_count, 2)

    def test_retained_launch_test_module_is_shared_and_token_queries_stay_windows_only(self):
        names = {"src/owner_launch_tests.rs", "src/windows_token_probe.rs", "src/windows_token_probe_launch.rs"}

        def read(path):
            self.assertEqual(path.name, "owner_launch_tests.rs")
            return b"#[test]\nfn fixed() {}\n"

        with patch.object(build, "SOURCE", names), patch.object(build, "ordinary", side_effect=read):
            self.assertEqual(build.native_test_inventory(), {"owner::launch_tests::fixed"})

    def test_conpty_build_selector_and_source_separation_stay_closed(self):
        self.assertFalse(windows_build.diagnostic_selection([]))
        self.assertTrue(windows_build.diagnostic_selection(["--conpty-diagnostic"]))
        for arguments in (["auto"], ["--conpty-diagnostic", "extra"], ["--conpty-diagnostic", "--conpty-diagnostic"]):
            with self.assertRaises(ValueError):
                windows_build.diagnostic_selection(arguments)
        self.assertIn("patches/mxc-conpty-feature.patch", build.PATCHES)
        self.assertNotIn("patches/mxc-conpty-feature.patch", build.WINDOWS_SOURCE)
        self.assertIn("patches/mxc-owned-conpty-diagnostic.patch", build.WINDOWS_SOURCE)
        self.assertEqual(len(windows_build.INERT_TESTS), 21)
        self.assertEqual(len(windows_build.SDK_INERT_TESTS), 9)
        self.assertEqual(len(windows_build.CONPTY_TESTS), 4)
        self.assertEqual(len(windows_build.CONPTY_SDK_TESTS), 4)
        self.assertTrue(set(windows_build.INERT_TESTS).isdisjoint(windows_build.CONPTY_TESTS))
        self.assertTrue(set(windows_build.SDK_INERT_TESTS).isdisjoint(windows_build.CONPTY_SDK_TESTS))

    def test_same_reviewed_registry_and_exact_path_packages_admit(self):
        result = build.admit_lock(lock(), lock())
        self.assertEqual(result["registry_packages"], 1)
        self.assertEqual(result["new_registry_versions"], [])

    def test_new_version_checksum_and_git_source_refuse_before_compilation(self):
        for candidate in (
            lock(version="2.0.0"),
            lock(checksum="b" * 64),
            lock(source="git+https://example.invalid/code#fixed"),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(RuntimeError):
                build.admit_lock(lock(), candidate)

    def test_missing_and_extra_local_package_refuse(self):
        for paths in (set(), build.PATH_PACKAGES | {("unreviewed-local", "0.0.0")}):
            with self.subTest(paths=paths), self.assertRaises(RuntimeError):
                build.admit_lock(lock(), lock(paths=paths))

    def test_bounded_read_refuses_growth_after_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inert.txt"
            path.write_bytes(b"small")
            with patch.object(Path, "open", return_value=io.BytesIO(b"x" * 17)):
                with self.assertRaises(RuntimeError):
                    build.ordinary(path, 16)

    def test_empty_diagnostic_hash_is_retained_but_empty_source_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.stderr"
            path.write_bytes(b"")
            self.assertEqual(build.sha(path), build.hashlib.sha256(b"").hexdigest())
            with self.assertRaises(RuntimeError):
                build.ordinary(path)

    def test_dependency_unit_gate_inventory_is_seven_fixed_nonspawning_tests(self):
        self.assertEqual(sum(len(value["tests"]) for value in build.DEPENDENCY_TESTS.values()), 7)
        for value in build.DEPENDENCY_TESTS.values():
            self.assertEqual(len(value["tests"]), 3 if value["package"] == "axis-sandbox" else 4)
            self.assertTrue(all(name.startswith(value["prefix"]) for name in value["tests"]))

    def test_inert_c_evidence_refuses_missing_extra_reordered_or_incomplete_results(self):
        lines = [*build.C_TESTS, build.C_TEST_SUMMARY]
        build.admit_c_test_output("\n".join(lines) + "\n")
        for bad in (lines[:-1], lines[1:], [*lines, "extra"], [*reversed(lines[:-1]), lines[-1]]):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                build.admit_c_test_output("\n".join(bad) + "\n")

    def test_patch_path_traversal_refuses(self):
        self.assertEqual(build.patch_paths(b"+++ b/src/fixed.rs\n"), {"src/fixed.rs"})
        for name in (b"../escape", b"/absolute", b"src//alias", b"src/./alias"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                build.patch_paths(b"+++ b/" + name + b"\n")

    def test_build_environment_does_not_forward_tokens_or_loader_overrides(self):
        with (
            patch.dict(
                build.os.environ,
                {
                    "GITHUB_TOKEN": "fixed-public-canary",
                    "LD_PRELOAD": "fixed-public-canary",
                    "RUSTFLAGS": "fixed-public-canary",
                },
            ),
            patch.object(build.subprocess, "run") as run,
        ):
            run.return_value.stdout = "fixed"
            build.command(["fixed-build-tool"], capture=True)
            environment = run.call_args.kwargs["env"]
            self.assertFalse({"GITHUB_TOKEN", "LD_PRELOAD", "RUSTFLAGS"} & environment.keys())
            self.assertFalse(run.call_args.kwargs["shell"])
            self.assertEqual(run.call_args.kwargs["timeout"], 1800)

    @staticmethod
    def musl_elf(*, dynamic: bool = False) -> bytearray:
        data = bytearray(512)
        data[:7] = bytes([127]) + b"ELF" + bytes([2, 1, 1])
        build.struct.pack_into("<HHI", data, 16, 3 if dynamic else 2, 62, 1)
        build.struct.pack_into("<QQ", data, 24, 0x400080, 64)
        build.struct.pack_into("<HHH", data, 52, 64, 56, 3 if dynamic else 2)
        build.struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0, 512, 512, 4096)
        build.struct.pack_into("<IIQQQQQQ", data, 120, 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
        if dynamic:
            build.struct.pack_into("<IIQQQQQQ", data, 176, 2, 4, 384, 0x400180, 0, 32, 32, 8)
            build.struct.pack_into("<QQ", data, 384, 0x6FFFFFFB, 0)
            build.struct.pack_into("<QQ", data, 400, 0, 0)
        return data

    def test_static_rust_musl_elf_accepts_only_bounded_candidate_shapes(self):
        self.assertEqual(build.inspect_rust_musl_elf(bytes(self.musl_elf()))["kind"], "ET_EXEC_static")
        result = build.inspect_rust_musl_elf(bytes(self.musl_elf(dynamic=True)))
        self.assertEqual(result["kind"], "ET_DYN_static_PIE")
        self.assertTrue(result["pt_dynamic"])
        self.assertFalse(result["external_dependencies"])

    def test_static_rust_musl_elf_refuses_loader_dynamic_dependencies_and_wx(self):
        for tag in (1, 14, 15, 22, 29):
            candidate = self.musl_elf(dynamic=True)
            build.struct.pack_into("<QQ", candidate, 384, tag, 1)
            with self.subTest(tag=tag), self.assertRaises(RuntimeError):
                build.inspect_rust_musl_elf(bytes(candidate))
        for offset, value in ((64, 3), (68, 7), (124, 7)):
            candidate = self.musl_elf()
            build.struct.pack_into("<I", candidate, offset, value)
            with self.subTest(offset=offset), self.assertRaises(RuntimeError):
                build.inspect_rust_musl_elf(bytes(candidate))
        with self.assertRaises(RuntimeError):
            build.inspect_rust_musl_elf(bytes(self.musl_elf())[:95])
        entry_only_in_bss = self.musl_elf()
        build.struct.pack_into("<Q", entry_only_in_bss, 96, 0x80)
        with self.assertRaises(RuntimeError):
            build.inspect_rust_musl_elf(bytes(entry_only_in_bss))
        wrapped_address = self.musl_elf()
        build.struct.pack_into("<Q", wrapped_address, 80, (1 << 64) - 0x100)
        with self.assertRaises(RuntimeError):
            build.inspect_rust_musl_elf(bytes(wrapped_address))

    def test_static_rust_musl_toolchain_inventory_is_bounded_and_nonfollowing(self):
        with tempfile.TemporaryDirectory() as directory:
            rustlib = Path(directory) / "lib/rustlib" / build.MUSL_TARGET / "lib"
            rustlib.mkdir(parents=True)
            (rustlib / "libstd-fixed.rlib").write_bytes(b"fixed")
            inventory = build.rust_musl_toolchain_inventory(Path(directory))
            self.assertEqual(inventory["libstd-fixed.rlib"]["size"], 5)
            (rustlib / "empty.rlib").write_bytes(b"")
            with self.assertRaises(RuntimeError):
                build.rust_musl_toolchain_inventory(Path(directory))


if __name__ == "__main__":
    unittest.main()
