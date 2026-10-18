# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Synthetic artifact-boundary tests. No binary, Git or network is executed."""

from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
