# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Synthetic artifact-boundary tests. No binary, Git or network is executed."""

from __future__ import annotations

import importlib.util
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "windows_psec_verifier", Path(__file__).with_name("verify_live_artifact.py")
)
assert _SPEC is not None and _SPEC.loader is not None
verify = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verify)


class ArtifactVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = tempfile.TemporaryDirectory()
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name).resolve()
        self.artifact = self.root / "artifact"
        self.archive = self.root / "artifact.zip"
        self.commit = "a" * 40
        self.files = {name: ("synthetic:" + name).encode() for name in verify.FILES}
        self.files["source/Cargo.lock"] = b"synthetic reviewed combined lock\n"
        self.lock_sha = verify.sha256(self.files["source/Cargo.lock"])
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(verify, "COMBINED_LOCK_SHA256", self.lock_sha).start()
        self.files["TOOLCHAIN.txt"] = (
            b"rustc 1.95.0 (synthetic)\nhost: x86_64-pc-windows-msvc\ncargo 1.95.0 (synthetic)\n"
        )
        image = bytearray(128)
        image[:2] = b"MZ"
        struct.pack_into("<I", image, 60, 64)
        image[64:68] = b"PE\0\0"
        struct.pack_into("<H", image, 68, 0x8664)
        struct.pack_into("<H", image, 88, 0x20B)
        self.files[verify.BINARY] = bytes(image)  # Structural bytes only; never executable.
        self.files[verify.LOADER_BINARY] = bytes(image)
        self.sources = {verify.SOURCE_PREFIX + name: self.files["source/" + name] for name in verify.SOURCE_FILES}
        self.upstream = {}
        for name, commit, lock, license_name in [
            ("axis", verify.AXIS_COMMIT, "Cargo.lock", "LICENSE"),
            ("mxc", verify.MXC_COMMIT, "src/Cargo.lock", "LICENSE.md"),
        ]:
            for packaged, git_path in [
                (f"upstream/{name}-Cargo.lock", lock),
                (f"upstream/{name}-LICENSE", license_name),
            ]:
                self.files[packaged] = (name + "\r\n" + git_path + "\r\n").encode()
                self.upstream[(commit, git_path)] = self.files[packaged].replace(b"\r\n", b"\n")
        self.provenance = {
            "schema": "defenseclaw-contributor-axis-windows-psec-v1",
            "variant": verify.VARIANT,
            "axis_commit": verify.AXIS_COMMIT,
            "mxc_commit": verify.MXC_COMMIT,
            "combined_lock_sha256": self.lock_sha,
            "build_mode": "build-locked",
            "probe_executed": False,
            "human_lock_review_required_before_live_execution": True,
            "locked_rebuild": True,
            "scope": verify.SCOPE,
            "production_certification": False,
            "mxc_patched_paths": sorted(verify.PATCHED_PATHS),
            "upstream_lock_sha256": {
                name: verify.sha256(self.files[f"upstream/{name}-Cargo.lock"]) for name in ("axis", "mxc")
            },
            "mxc_patch_sha256": verify.sha256(self.files["source/patches/mxc-strict-windows-psec.patch"]),
        }
        self.workflow = {
            "repository": verify.REPOSITORY,
            "workflow_commit": self.commit,
            "run_id": "123",
            "run_attempt": "1",
            "execution_performed": False,
        }
        self.write_artifact()

    def write_artifact(self) -> None:
        self.provenance["files"] = {name: verify.sha256(data) for name, data in self.files.items()}
        for name, content in self.files.items():
            path = self.artifact / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        for name, value in [("PROVENANCE.json", self.provenance), ("WORKFLOW.json", self.workflow)]:
            (self.artifact / name).write_text(json.dumps(value), encoding="utf-8")
        with zipfile.ZipFile(self.archive, "w") as bundle:
            for name in sorted(verify.ALL_FILES):
                bundle.write(self.artifact / name, "build-artifact/" + name)
            bundle.writestr("Cargo.lock", self.files["source/Cargo.lock"])

    def git_blob(self, _checkout: Path, commit: str, relative: str) -> bytes:
        return self.sources[relative] if commit == self.commit else self.upstream[(commit, relative)]

    def run_verify(self) -> dict:
        with (
            mock.patch.object(verify, "git_blob", side_effect=self.git_blob),
            mock.patch.object(verify, "verify_github"),
        ):
            return verify.verify(
                self.artifact,
                self.archive,
                self.root,
                self.root,
                self.root,
                verify.sha256(self.archive.read_bytes()),
                verify.sha256((self.artifact / "PROVENANCE.json").read_bytes()),
                self.commit,
                123,
                456,
            )

    def test_locked_source_bound_fixture_verifies_without_execution(self) -> None:
        result = self.run_verify()
        self.assertTrue(result["verified"])
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["production_certification"])

    def test_generate_lock_build_cannot_be_certified(self) -> None:
        self.provenance["build_mode"] = "generate-lock"
        self.provenance["locked_rebuild"] = False
        self.write_artifact()
        with self.assertRaisesRegex(ValueError, "build contract"):
            self.run_verify()

    def test_original_headless_artifact_cannot_be_accepted_as_loader_diagnostic(self) -> None:
        self.provenance.pop("variant")
        self.provenance["scope"] = "fixed_windows_native_psec_only_headless"
        self.write_artifact()
        with self.assertRaisesRegex(ValueError, "build contract"):
            self.run_verify()

    def test_source_self_attestation_does_not_replace_git_blob(self) -> None:
        self.files["source/src/probe.rs"] = b"unreviewed source"
        self.write_artifact()
        with self.assertRaisesRegex(ValueError, "source Git blob differs"):
            self.run_verify()

    def test_tampered_binary_is_refused(self) -> None:
        (self.artifact / verify.BINARY).write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "artifact file changed"):
            self.run_verify()

    def test_unknown_empty_directory_is_refused(self) -> None:
        (self.artifact / "unreviewed").mkdir()
        with self.assertRaisesRegex(ValueError, "unreviewed artifact directory"):
            self.run_verify()

    def test_zip_path_escape_is_refused(self) -> None:
        with zipfile.ZipFile(self.archive, "a") as bundle:
            bundle.writestr("../escape", "synthetic")
        with self.assertRaisesRegex(ValueError, "unreviewed ZIP entry"):
            self.run_verify()

    def test_github_source_binding_is_required(self) -> None:
        artifact = {
            "id": 456,
            "name": "axis-mxc-v1-windows-contributor-" + self.commit,
            "expired": False,
            "digest": "sha256:" + "b" * 64,
            "workflow_run": {"id": 123, "head_sha": "c" * 40},
        }
        with (
            mock.patch.object(verify, "github_json", side_effect=[artifact, {}]),
            self.assertRaisesRegex(ValueError, "artifact identity"),
        ):
            verify.verify_github(456, 123, self.commit, "b" * 64)


class BoundaryArtifactVerificationTests(ArtifactVerificationTests):
    def setUp(self) -> None:
        super().setUp()
        self.mode = "standalone-boundary"
        contract = verify.artifact_contract(self.mode)
        for name, git_path in contract["sources"].items():
            if "source/" + name not in self.files:
                self.files["source/" + name] = ("synthetic:" + name).encode()
            self.sources[git_path] = self.files["source/" + name]
        self.files[verify.BOUNDARY_BINARY] = self.files[verify.BINARY]
        literal = verify.sha256(self.files["source/patches/mxc-literal-argv.patch"])
        windows = verify.sha256(self.files["source/patches/mxc-windows-literal-argv.patch"])
        identity = verify.sha256(self.files["source/patches/mxc-windows-process-identity.patch"])
        sdk_lock = verify.sha256(self.files["upstream/mxc-Cargo.lock"])
        mock.patch.object(verify, "LITERAL_OVERLAY_SHA256", literal).start()
        mock.patch.object(verify, "BOUNDARY_OVERLAY_SHA256", windows).start()
        mock.patch.object(verify, "IDENTITY_OVERLAY_SHA256", identity).start()
        mock.patch.object(verify, "SDK_LOCK_SHA256", sdk_lock).start()
        self.provenance.update(
            variant=verify.BOUNDARY_VARIANT,
            scope=verify.BOUNDARY_SCOPE,
            mxc_patched_paths=sorted(verify.BOUNDARY_MODIFIED_PATHS),
            mxc_added_paths=sorted(verify.BOUNDARY_ADDED_PATHS),
            mxc_overlay_file_sha256=dict(verify.BOUNDARY_OVERLAY_FILES),
            mxc_literal_argv_patch_sha256=literal,
            mxc_literal_argv_patch_source="test/e2e/axis/patches/mxc-literal-argv.patch",
            mxc_windows_argv_patch_sha256=windows,
            mxc_windows_process_identity_patch_sha256=identity,
            pure_native_environment_tests_passed=True,
            pure_native_environment_tests=verify.PURE_ENVIRONMENT_TESTS,
        )
        self.admission = {
            "tests": list(verify.SDK_TESTS),
            "passed": len(verify.SDK_TESTS),
            "sandbox_or_payload_execution": False,
            "native_file_fixture_tests": 1,
            "upstream_lock_sha256": sdk_lock,
        }
        self.write_artifact()

    def write_artifact(self) -> None:
        if not hasattr(self, "mode"):
            return super().write_artifact()
        self.provenance["files"] = {name: verify.sha256(data) for name, data in self.files.items()}
        for name, data in self.files.items():
            target = self.artifact / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        for name, value in [
            ("PROVENANCE.json", self.provenance),
            ("WORKFLOW.json", self.workflow),
            ("SDK-ADMISSION-TESTS.json", self.admission),
        ]:
            (self.artifact / name).write_text(json.dumps(value), encoding="utf-8")
        with zipfile.ZipFile(self.archive, "w") as bundle:
            for name in sorted(verify.artifact_contract(self.mode)["all_files"]):
                bundle.write(self.artifact / name, "build-artifact/" + name)
            bundle.writestr("Cargo.lock", self.files["source/Cargo.lock"])

    def run_verify(self, mode: str | None = None) -> dict:
        with (
            mock.patch.object(verify, "git_blob", side_effect=self.git_blob),
            mock.patch.object(verify, "verify_github"),
        ):
            return verify.verify(
                self.artifact,
                self.archive,
                self.root,
                self.root,
                self.root,
                verify.sha256(self.archive.read_bytes()),
                verify.sha256((self.artifact / "PROVENANCE.json").read_bytes()),
                self.commit,
                123,
                456,
                self.mode if mode is None else mode,
            )

    def test_boundary_cannot_be_accepted_as_loader_mode(self) -> None:
        with self.assertRaisesRegex(ValueError, "build contract"):
            self.run_verify("loader-only")

    def test_identity_artifact_cannot_be_accepted_as_four_image_dll_mode(self) -> None:
        with self.assertRaisesRegex(ValueError, "build contract"):
            self.run_verify("dll-startup-only")

    def test_boundary_requires_exact_nonignored_sdk_test_evidence(self) -> None:
        for name, value in [("passed", 9), ("native_file_fixture_tests", True), ("sandbox_or_payload_execution", 0)]:
            with self.subTest(name=name):
                original = self.admission[name]
                self.admission[name] = value
                self.write_artifact()
                with self.assertRaisesRegex(ValueError, "SDK admission test evidence"):
                    self.run_verify()
                self.admission[name] = original

    def test_forged_added_source_fingerprint_is_refused(self) -> None:
        self.provenance["mxc_overlay_file_sha256"][sorted(verify.BOUNDARY_ADDED_PATHS)[0]] = "0" * 64
        self.write_artifact()
        with self.assertRaisesRegex(ValueError, "SDK source fingerprint digest"):
            self.run_verify()

    def test_native_identity_overlay_is_independently_pinned(self) -> None:
        self.provenance["mxc_windows_process_identity_patch_sha256"] = "0" * 64
        self.write_artifact()
        with self.assertRaisesRegex(ValueError, "native identity overlay differs"):
            self.run_verify()

    def test_native_environment_pure_tests_cannot_be_omitted(self) -> None:
        self.provenance["pure_native_environment_tests_passed"] = False
        self.write_artifact()
        with self.assertRaisesRegex(ValueError, "pure native environment test evidence"):
            self.run_verify()

    def test_native_environment_pure_inventory_matches_build_source(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "fixed_native_environment_build", Path(__file__).with_name("prepare_build.py")
        )
        assert spec is not None and spec.loader is not None
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        self.assertEqual(build.PURE_ENVIRONMENT_TESTS, verify.PURE_ENVIRONMENT_TESTS)
        self.assertEqual(sum(map(len, verify.PURE_ENVIRONMENT_TESTS.values())), 6)

    def test_third_image_change_is_refused(self) -> None:
        (self.artifact / verify.BOUNDARY_BINARY).write_bytes(b"changed third image")
        with self.assertRaisesRegex(ValueError, "artifact file changed"):
            self.run_verify()


class DLLArtifactVerificationTests(BoundaryArtifactVerificationTests):
    def setUp(self) -> None:
        super().setUp()
        self.mode = "dll-startup-only"
        contract = verify.artifact_contract(self.mode)
        for name, git_path in contract["sources"].items():
            if "source/" + name not in self.files:
                self.files["source/" + name] = ("synthetic:" + name).encode()
            self.sources[git_path] = self.files["source/" + name]
        self.files[verify.DLL_BINARY] = self.files[verify.BINARY]
        self.provenance.update(
            variant=verify.DLL_VARIANT,
            scope=verify.DLL_SCOPE,
            pure_dll_startup_tests=verify.PURE_DLL_TESTS,
            pure_dll_startup_tests_passed=True,
        )
        self.write_artifact()

    def test_identity_artifact_cannot_be_accepted_as_four_image_dll_mode(self) -> None:
        # This subclass intentionally owns a distinct four-image artifact.
        self.assertEqual(len(self.run_verify()["binaries"]), 4)
        with self.assertRaisesRegex(ValueError, "build contract"):
            self.run_verify("standalone-boundary")

    def test_fourth_image_and_fixed_source_cannot_change(self) -> None:
        (self.artifact / verify.DLL_BINARY).write_bytes(b"changed fourth PE")
        with self.assertRaisesRegex(ValueError, "artifact file changed"):
            self.run_verify()
        self.write_artifact()
        self.files["source/src/dll_startup_child.rs"] = b"unreviewed DLL child"
        self.write_artifact()
        with self.assertRaisesRegex(ValueError, "source Git blob differs"):
            self.run_verify()

    def test_dll_pure_test_receipt_and_builder_inventory_are_exact(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "fixed_dll_build", Path(__file__).with_name("prepare_build.py")
        )
        assert spec is not None and spec.loader is not None
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        self.assertEqual(build.PURE_DLL_TESTS, verify.PURE_DLL_TESTS)
        self.assertEqual(sum(map(len, verify.PURE_DLL_TESTS.values())), 4)
        for name, changed in [
            ("pure_dll_startup_tests_passed", False),
            ("pure_dll_startup_tests", {}),
        ]:
            with self.subTest(name=name):
                original = self.provenance[name]
                self.provenance[name] = changed
                self.write_artifact()
                with self.assertRaisesRegex(ValueError, "pure DLL startup test evidence"):
                    self.run_verify()
                self.provenance[name] = original

class BoundedFileTests(unittest.TestCase):
    def test_growth_after_stat_cannot_exceed_the_read_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "synthetic.bin"
            path.write_bytes(b"x")
            source = io.BytesIO(b"grown")
            with mock.patch.object(Path, "open", return_value=source):
                with self.assertRaisesRegex(ValueError, "grew beyond its read bound"):
                    verify.ordinary_file(path, 4)
            self.assertTrue(source.closed)


class GitHubBuildAdmissionTests(unittest.TestCase):
    def test_isolated_branch_requires_explicit_boundary_dispatch(self) -> None:
        commit, digest = "a" * 40, "b" * 64
        artifact = {
            "id": 456,
            "name": "axis-mxc-v1-windows-contributor-" + commit,
            "expired": False,
            "digest": "sha256:" + digest,
            "workflow_run": {"id": 123, "head_sha": commit},
        }
        baseline = {
            "id": 123,
            "head_sha": commit,
            "path": verify.WORKFLOW,
            "repository": {"full_name": verify.REPOSITORY},
            "head_repository": {"full_name": verify.REPOSITORY},
            "status": "completed",
            "conclusion": "success",
        }
        for mode, branch, event, accepted in [
            ("loader-only", "codex/axis-sandbox-feasibility", "push", True),
            ("standalone-boundary", "codex/axis-native-build", "workflow_dispatch", True),
            ("standalone-boundary", "codex/axis-peer-experiments", "workflow_dispatch", True),
            ("dll-startup-only", "codex/axis-peer-experiments", "workflow_dispatch", True),
            ("dll-startup-only", "codex/axis-native-build", "push", False),
            ("loader-only", "codex/axis-native-build", "workflow_dispatch", False),
            ("loader-only", "codex/axis-peer-experiments", "workflow_dispatch", False),
            ("standalone-boundary", "codex/axis-native-build", "push", False),
            ("standalone-boundary", "codex/axis-peer-experiments", "push", False),
            ("standalone-boundary", "codex/axis-peer-experiments", "pull_request", False),
            ("standalone-boundary", "unreviewed-branch", "workflow_dispatch", False),
        ]:
            with self.subTest(mode=mode, branch=branch, event=event):
                run = {**baseline, "head_branch": branch, "event": event}
                with mock.patch.object(verify, "github_json", side_effect=[artifact, run]):
                    if accepted:
                        verify.verify_github(456, 123, commit, digest, mode)
                    else:
                        with self.assertRaisesRegex(ValueError, "workflow did not succeed"):
                            verify.verify_github(456, 123, commit, digest, mode)

        admitted = {**baseline, "head_branch": "codex/axis-peer-experiments", "event": "workflow_dispatch"}
        for key, changed in [
            ("head_sha", "c" * 40),
            ("repository", {"full_name": "unreviewed/defenseclaw"}),
            ("head_repository", {"full_name": "unreviewed/defenseclaw"}),
            ("path", ".github/workflows/unreviewed.yml"),
            ("conclusion", "failure"),
            ("status", "in_progress"),
        ]:
            with (
                self.subTest(changed=key),
                mock.patch.object(verify, "github_json", side_effect=[artifact, {**admitted, key: changed}]),
                self.assertRaisesRegex(ValueError, "workflow did not succeed"),
            ):
                verify.verify_github(456, 123, commit, digest, "standalone-boundary")


if __name__ == "__main__":
    unittest.main()
