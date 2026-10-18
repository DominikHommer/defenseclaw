#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Verify the reviewed Windows PSEC contributor artifact. Never executes it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import struct
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

REPOSITORY = "cisco-ai-defense/defenseclaw"
WORKFLOW = ".github/workflows/axis-mxc-v1-windows-build.yml"
AXIS_COMMIT = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC_COMMIT = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
# Independently reviewed by the root agent before the first locked rebuild.
COMBINED_LOCK_SHA256 = "3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69"
BINARY = "bin/defenseclaw-axis-windows-psec-probe.exe"
LOADER_BINARY = "bin/defenseclaw-axis-windows-psec-loader-child.exe"
VARIANT = "separate_std_loader_diagnostic"
SCOPE = "fixed_windows_native_psec_loader_diagnostic"
SOURCE_PREFIX = "test/e2e/axis/windows/mxc-v1/"
SOURCE_FILES = {
    "Cargo.toml",
    "Cargo.lock",
    "prepare_build.py",
    "test_prepare_build.py",
    "README.md",
    "src/main.rs",
    "src/probe.rs",
    "src/loader_child.rs",
    "patches/mxc-strict-windows-psec.patch",
}
PATCHED_PATHS = {
    "src/mxc-sdk/src/lib.rs",
    "src/mxc-sdk/src/core/mxc_engine/mod.rs",
    "src/mxc-sdk/src/core/mxc_engine/dispatch.rs",
    "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs",
}
FILES = {"source/" + name for name in SOURCE_FILES} | {
    BINARY,
    LOADER_BINARY,
    "TOOLCHAIN.txt",
    "upstream/axis-Cargo.lock",
    "upstream/mxc-Cargo.lock",
    "upstream/axis-LICENSE",
    "upstream/mxc-LICENSE",
}
ALL_FILES = FILES | {"PROVENANCE.json", "WORKFLOW.json"}
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 96 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_argument(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError("expected a lowercase SHA256 digest")
    return value


def commit_argument(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise argparse.ArgumentTypeError("expected an exact lowercase Git commit")
    return value


def ordinary_file(path: Path, bound: int = MAX_FILE_BYTES) -> bytes:
    for component in [path, *path.parents]:
        metadata = component.lstat()
        require(not stat.S_ISLNK(metadata.st_mode), "symlink path refused")
        require(not getattr(metadata, "st_file_attributes", 0) & 0x400, "reparse-point path refused")
    metadata = path.stat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= bound, "file type or size differs")
    return path.read_bytes()


def payload_file(root: Path, name: str) -> bytes:
    require(name in ALL_FILES, "path outside the exact artifact inventory")
    return ordinary_file(root.joinpath(*PurePosixPath(name).parts))


def exact_inventory(root: Path) -> set[str]:
    directories = {str(parent) for name in ALL_FILES for parent in PurePosixPath(name).parents if str(parent) != "."}
    pending = [root]
    files = set()
    entries = 0
    while pending:
        for path in pending.pop().iterdir():
            entries += 1
            require(entries <= 64, "too many extracted artifact entries")
            metadata = path.lstat()
            require(
                not stat.S_ISLNK(metadata.st_mode) and not getattr(metadata, "st_file_attributes", 0) & 0x400,
                "artifact reparse point refused",
            )
            name = path.relative_to(root).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                require(name in directories, "unreviewed artifact directory")
                pending.append(path)
            else:
                require(name in ALL_FILES and stat.S_ISREG(metadata.st_mode), "unreviewed artifact entry")
                files.add(name)
    return files


def git_blob(checkout: Path, commit: str, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(checkout), "show", commit + ":" + relative],
        check=True,
        shell=False,
        capture_output=True,
        timeout=20,
    )
    require(len(result.stdout) <= MAX_FILE_BYTES, "reviewed Git object exceeds its bound")
    return result.stdout


def github_json(endpoint: str) -> dict:
    result = subprocess.run(
        ["gh", "api", "repos/" + REPOSITORY + "/actions/" + endpoint],
        check=True,
        shell=False,
        capture_output=True,
        timeout=30,
    )
    require(len(result.stdout) <= 2 * 1024 * 1024, "GitHub response exceeds its bound")
    value = json.loads(result.stdout)
    require(isinstance(value, dict), "GitHub metadata must be an object")
    return value


def verify_github(artifact_id: int, run_id: int, build_commit: str, archive_sha256: str) -> None:
    artifact = github_json(f"artifacts/{artifact_id}")
    run = github_json(f"runs/{run_id}")
    require(
        artifact.get("id") == artifact_id
        and artifact.get("name") == "axis-mxc-v1-windows-contributor-" + build_commit
        and artifact.get("expired") is False
        and artifact.get("digest") == "sha256:" + archive_sha256
        and artifact.get("workflow_run", {}).get("id") == run_id
        and artifact.get("workflow_run", {}).get("head_sha") == build_commit,
        "GitHub artifact identity, source or digest differs",
    )
    require(
        run.get("id") == run_id
        and run.get("head_sha") == build_commit
        and run.get("path") == WORKFLOW
        and run.get("head_branch") == "codex/axis-sandbox-feasibility"
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and run.get("head_repository", {}).get("full_name") == REPOSITORY
        and run.get("event") in {"push", "workflow_dispatch"}
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "the exact native Windows build workflow did not succeed",
    )


def verify_archive(archive: Path, artifact: Path, archive_sha256: str) -> None:
    require(sha256(ordinary_file(archive, MAX_ARCHIVE_BYTES)) == archive_sha256, "outer archive digest differs")
    expected = {"build-artifact/" + name for name in ALL_FILES} | {"Cargo.lock"}
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        require(len(members) <= 64, "too many ZIP entries")
        names = set()
        folded = set()
        total = 0
        for member in members:
            name = member.filename
            require(name not in names and name.casefold() not in folded, "duplicate ZIP path")
            names.add(name)
            folded.add(name.casefold())
            require(not member.is_dir() and name in expected, "unreviewed ZIP entry")
            require((member.external_attr >> 16) & 0o170000 != 0o120000, "ZIP symlink refused")
            require(member.file_size <= MAX_FILE_BYTES, "oversized ZIP entry")
            total += member.file_size
            require(total <= MAX_ARCHIVE_BYTES, "oversized ZIP payload")
            relative = name.removeprefix("build-artifact/") if name != "Cargo.lock" else "source/Cargo.lock"
            require(bundle.read(member) == payload_file(artifact, relative), "ZIP and extracted artifact differ")
        require(names == expected, "ZIP inventory differs")


def verify(
    artifact: Path,
    archive: Path,
    checkout: Path,
    axis: Path,
    mxc: Path,
    archive_sha256: str,
    provenance_sha256: str,
    build_commit: str,
    run_id: int,
    artifact_id: int,
) -> dict:
    require(artifact.is_absolute() and artifact.is_dir(), "absolute extracted artifact directory required")
    provenance_raw = payload_file(artifact, "PROVENANCE.json")
    require(sha256(provenance_raw) == provenance_sha256, "external provenance pin differs")
    provenance = json.loads(provenance_raw)
    require(isinstance(provenance, dict), "provenance must be an object")
    required = {
        "schema": "defenseclaw-contributor-axis-windows-psec-v1",
        "variant": VARIANT,
        "axis_commit": AXIS_COMMIT,
        "mxc_commit": MXC_COMMIT,
        "combined_lock_sha256": COMBINED_LOCK_SHA256,
        "build_mode": "build-locked",
        "probe_executed": False,
        "human_lock_review_required_before_live_execution": True,
        "locked_rebuild": True,
        "scope": SCOPE,
        "production_certification": False,
        "mxc_patched_paths": sorted(PATCHED_PATHS),
    }
    for key, expected in required.items():
        require(
            type(provenance.get(key)) is type(expected) and provenance[key] == expected,
            "build contract differs: " + key,
        )
    inventory = provenance.get("files")
    require(isinstance(inventory, dict) and set(inventory) == FILES, "provenance inventory differs")
    actual = exact_inventory(artifact)
    require(actual == ALL_FILES, "extracted artifact has missing or additional files")
    for name, expected in inventory.items():
        require(
            isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "invalid file digest"
        )
        require(sha256(payload_file(artifact, name)) == expected, "artifact file changed: " + name)
    for name in SOURCE_FILES:
        require(
            payload_file(artifact, "source/" + name) == git_blob(checkout, build_commit, SOURCE_PREFIX + name),
            "source Git blob differs: " + name,
        )
    require(
        sha256(payload_file(artifact, "source/Cargo.lock")) == COMBINED_LOCK_SHA256, "reviewed combined lock differs"
    )
    upstream_hashes = {}
    for name, source, commit, lock, license_name in [
        ("axis", axis, AXIS_COMMIT, "Cargo.lock", "LICENSE"),
        ("mxc", mxc, MXC_COMMIT, "src/Cargo.lock", "LICENSE.md"),
    ]:
        for packaged, git_path in [(f"upstream/{name}-Cargo.lock", lock), (f"upstream/{name}-LICENSE", license_name)]:
            raw = payload_file(artifact, packaged)
            git_bytes = git_blob(source, commit, git_path)
            require(
                raw == git_bytes or raw.replace(b"\r\n", b"\n") == git_bytes, "upstream Git bytes differ: " + packaged
            )
            if git_path == lock:
                upstream_hashes[name] = sha256(raw)
    require(provenance.get("upstream_lock_sha256") == upstream_hashes, "raw upstream lock digests differ")
    require(
        sha256(payload_file(artifact, "source/patches/mxc-strict-windows-psec.patch"))
        == provenance.get("mxc_patch_sha256"),
        "reviewed SDK overlay differs",
    )
    toolchain = payload_file(artifact, "TOOLCHAIN.txt")
    require(
        toolchain.startswith(b"rustc 1.95.0 ")
        and b"host: x86_64-pc-windows-msvc" in toolchain
        and b"cargo 1.95.0 " in toolchain,
        "compiler identity differs",
    )
    binaries = []
    for relative in (BINARY, LOADER_BINARY):
        binary = payload_file(artifact, relative)
        require(len(binary) >= 64 and binary[:2] == b"MZ", "native PE image required")
        pe = struct.unpack_from("<I", binary, 60)[0]
        require(
            pe + 26 <= len(binary)
            and binary[pe : pe + 4] == b"PE\0\0"
            and struct.unpack_from("<H", binary, pe + 4)[0] == 0x8664
            and struct.unpack_from("<H", binary, pe + 24)[0] == 0x20B,
            "native x64 PE image required",
        )
        binaries.append({"path": relative, "sha256": inventory[relative], "size": len(binary)})
    workflow = json.loads(payload_file(artifact, "WORKFLOW.json"))
    require(
        isinstance(workflow, dict)
        and workflow.get("repository") == REPOSITORY
        and workflow.get("workflow_commit") == build_commit
        and workflow.get("run_id") == str(run_id)
        and workflow.get("execution_performed") is False,
        "workflow attribution differs",
    )
    verify_archive(archive, artifact, archive_sha256)
    verify_github(artifact_id, run_id, build_commit, archive_sha256)
    return {
        "verified": True,
        "execution_performed": False,
        "scope": required["scope"],
        "variant": VARIANT,
        "axis_commit": AXIS_COMMIT,
        "mxc_commit": MXC_COMMIT,
        "build_commit": build_commit,
        "build_run": run_id,
        "artifact_id": artifact_id,
        "archive_sha256": archive_sha256,
        "provenance_sha256": provenance_sha256,
        "combined_lock_sha256": COMBINED_LOCK_SHA256,
        "artifact": str(artifact),
        "binary": BINARY,
        "binary_sha256": inventory[BINARY],
        "binary_size": binaries[0]["size"],
        "binaries": binaries,
        "production_certification": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("artifact", "archive", "source-checkout", "axis-source", "mxc-source", "receipt"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("archive-sha256", "provenance-sha256"):
        parser.add_argument("--" + name, type=digest_argument, required=True)
    parser.add_argument("--build-commit", type=commit_argument, required=True)
    parser.add_argument("--build-run", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    args = parser.parse_args()
    require(args.build_run > 0 and args.artifact_id > 0, "positive exact GitHub IDs required")
    result = verify(
        args.artifact,
        args.archive,
        args.source_checkout,
        args.axis_source,
        args.mxc_source,
        args.archive_sha256,
        args.provenance_sha256,
        args.build_commit,
        args.build_run,
        args.artifact_id,
    )
    with args.receipt.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
