#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build-only contributor artifact preparation. Never runs the probe binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path

AXIS_COMMIT = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC_COMMIT = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
TOOLCHAIN = "1.95.0"
BINARY = "defenseclaw-axis-windows-psec-probe.exe"
LOADER_BINARY = "defenseclaw-axis-windows-psec-loader-child.exe"
BOUNDARY_BINARY = "defenseclaw-axis-windows-psec-boundary-child.exe"
ROOT = Path(__file__).resolve().parent
PATCH = ROOT / "patches" / "mxc-strict-windows-psec.patch"
LITERAL_PATCH = ROOT / "patches" / "mxc-literal-argv.patch"
WINDOWS_ARGV_PATCH = ROOT / "patches" / "mxc-windows-literal-argv.patch"
LITERAL_PATCH_SOURCE = "test/e2e/axis/patches/mxc-literal-argv.patch"
LITERAL_PATCH_SHA256 = "7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d"
WINDOWS_ARGV_PATCH_PATHS = {
    "src/mxc-sdk/src/lib.rs",
    "src/mxc-sdk/src/core/mxc_engine/mod.rs",
    "src/mxc-sdk/src/core/mxc_engine/dispatch.rs",
    "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs",
}
PATCHED_PATHS = {
    "src/mxc-sdk/src/lib.rs",
    "src/mxc-sdk/src/core/mxc_engine/mod.rs",
    "src/mxc-sdk/src/core/mxc_engine/dispatch.rs",
    "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs",
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_command.rs",
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_runner.rs",
    "src/mxc-sdk/src/backends/seatbelt/common/seatbelt_runner.rs",
    "src/mxc-sdk/src/core/mxc_common/mod.rs",
    "src/mxc-sdk/src/core/mxc_common/sandbox_process.rs",
    "src/mxc-sdk/src/core/mxc_common/validator.rs",
    "src/mxc-sdk/src/policy.rs",
    "src/mxc-sdk/src/policy/exact/mod.rs",
}
ADDED_PATHS = {
    "src/mxc-sdk/src/core/mxc_common/literal_argv.rs",
    "src/mxc-sdk/src/core/mxc_engine/literal_argv.rs",
    "src/mxc-sdk/src/literal_argv.rs",
}


def command(argv: list[str], *, cwd: Path = ROOT, capture: bool = False) -> str:
    # Build tooling is already provisioned by the disposable CI job. Do not
    # forward tokens, loader overrides or caller Rust flags to build scripts.
    environment = {
        key: os.environ[key]
        for key in (
            "PATH",
            "HOME",
            "USERPROFILE",
            "SYSTEMROOT",
            "SystemRoot",
            "WINDIR",
            "TEMP",
            "TMP",
            "APPDATA",
            "LOCALAPPDATA",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "SSL_CERT_FILE",
            "CARGO_HTTP_CAINFO",
            "INCLUDE",
            "LIB",
            "LIBPATH",
            "VCINSTALLDIR",
            "VCToolsInstallDir",
            "WindowsSdkDir",
            "WindowsSDKVersion",
        )
        if key in os.environ
    }
    environment.update(CARGO_TERM_COLOR="never", CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2")
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        check=True,
        shell=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        timeout=2400,
    )
    return result.stdout.strip() if capture else ""


def verify_source(directory: str, expected: str) -> Path:
    source = ROOT / directory
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError(f"provision a fresh exact-commit checkout at {directory}")
    if command(["git", "rev-parse", "HEAD"], cwd=source, capture=True) != expected:
        raise RuntimeError(f"{directory} is not at the reviewed commit")
    if command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, capture=True):
        raise RuntimeError(f"{directory} must be clean before the reviewed overlay is applied")
    return source


def verify_build_sources(axis: Path, mxc: Path) -> None:
    """Reject source drift, index writes and new files around the build."""
    for source, expected in ((axis, AXIS_COMMIT), (mxc, MXC_COMMIT)):
        if command(["git", "rev-parse", "HEAD"], cwd=source, capture=True) != expected:
            raise RuntimeError("an upstream source commit changed during the build")
        status = command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, capture=True)
        # command() strips surrounding whitespace; strip each expected status
        # line too, without accepting staged, added or untracked content.
        actual = {line.strip() for line in status.splitlines()}
        expected_status = (
            {f"M {path}" for path in PATCHED_PATHS} | {f"?? {path}" for path in ADDED_PATHS} if source == mxc else set()
        )
        if actual != expected_status:
            raise RuntimeError("upstream source changes differ from the reviewed MXC overlay paths")
        staged = command(["git", "diff", "--cached", "--name-only"], cwd=source, capture=True)
        if staged:
            raise RuntimeError("upstream source staging is not permitted")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def overlay_fingerprints(mxc: Path) -> dict[str, str]:
    """Include newly added files: Git's unstaged diff does not contain them."""
    result = {}
    for relative in sorted(PATCHED_PATHS | ADDED_PATHS):
        path = mxc / relative
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            or metadata.st_size > 2 * 1024 * 1024
        ):
            raise RuntimeError("reviewed MXC overlay target must be a bounded regular file")
        result[relative] = digest(path)
    return result


def verify_windows_patch_paths(mxc: Path) -> None:
    rows = command(["git", "apply", "--numstat", str(WINDOWS_ARGV_PATCH)], cwd=mxc, capture=True).splitlines()
    fields = [row.split("\t") for row in rows]
    if (
        len(fields) != len(WINDOWS_ARGV_PATCH_PATHS)
        or any(len(row) != 3 or not row[0].isdigit() or not row[1].isdigit() for row in fields)
        or {row[2] for row in fields} != WINDOWS_ARGV_PATCH_PATHS
    ):
        raise RuntimeError("Windows argv overlay must touch exactly its four reviewed source paths")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("generate-lock", "build-locked"))
    args = parser.parse_args()
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("build this contributor artifact on native Windows x86_64")
    artifact = ROOT / "build-artifact"
    if artifact.exists() or artifact.is_symlink():
        raise RuntimeError("build-artifact already exists; use a fresh contributor staging directory")
    lock = ROOT / "Cargo.lock"
    if args.mode == "generate-lock" and (lock.exists() or lock.is_symlink()):
        raise RuntimeError("generate-lock requires a fresh staging directory without Cargo.lock")
    if args.mode == "build-locked" and (lock.is_symlink() or not lock.is_file()):
        raise RuntimeError("build-locked requires the reviewed combined Cargo.lock")
    axis = verify_source("axis-source", AXIS_COMMIT)
    mxc = verify_source("mxc-source", MXC_COMMIT)
    toolchain = command(["rustc", f"+{TOOLCHAIN}", "-Vv"], capture=True)
    cargo_version = command(["cargo", f"+{TOOLCHAIN}", "--version"], capture=True)
    if not toolchain.startswith(f"rustc {TOOLCHAIN} "):
        raise RuntimeError("the already-installed Rust toolchain differs from the reviewed version")
    upstream_locks = {"axis": digest(axis / "Cargo.lock"), "mxc": digest(mxc / "src" / "Cargo.lock")}
    if not LITERAL_PATCH.is_file() or digest(LITERAL_PATCH) != LITERAL_PATCH_SHA256:
        raise RuntimeError("stage the exact reviewed shared literal-argv patch from Git before building")
    verify_windows_patch_paths(mxc)
    for patch in (PATCH, LITERAL_PATCH, WINDOWS_ARGV_PATCH):
        command(["git", "apply", "--check", str(patch)], cwd=mxc)
        command(["git", "apply", str(patch)], cwd=mxc)
    verify_build_sources(axis, mxc)
    overlay_before = overlay_fingerprints(mxc)
    if args.mode == "generate-lock":
        command(["cargo", f"+{TOOLCHAIN}", "generate-lockfile"])
    lock_before = digest(lock)
    command(["cargo", f"+{TOOLCHAIN}", "build", "--locked", "--release"])
    # Compile the probe's test target without executing any newly built code.
    command(["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--release", "--no-run"])
    # Run only this exact pure spelling test outside a sandbox. It performs no
    # filesystem query, environment lookup, process creation or PSEC operation.
    spelling_test = "tests::private_environment_only_accepts_exact_local_disk_prefix_difference"
    spelling_output = command(
        [
            "cargo",
            f"+{TOOLCHAIN}",
            "test",
            "--locked",
            "--release",
            "--bin",
            "defenseclaw-axis-windows-psec-boundary-child",
            spelling_test,
            "--",
            "--exact",
        ],
        capture=True,
    )
    if (
        f"test {spelling_test} ... ok" not in spelling_output
        or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in spelling_output
    ):
        raise RuntimeError("fixed private environment spelling test did not pass exactly once")
    if digest(lock) != lock_before:
        raise RuntimeError("the combined dependency lock changed during the locked build")
    if upstream_locks != {"axis": digest(axis / "Cargo.lock"), "mxc": digest(mxc / "src" / "Cargo.lock")}:
        raise RuntimeError("an upstream lock changed during the build")
    verify_build_sources(axis, mxc)
    if overlay_fingerprints(mxc) != overlay_before:
        raise RuntimeError("reviewed MXC overlay bytes changed during the build")

    (artifact / "bin").mkdir(parents=True)
    files = [
        Path("Cargo.toml"),
        Path("Cargo.lock"),
        Path("prepare_build.py"),
        Path("test_prepare_build.py"),
        Path("README.md"),
        Path("src/main.rs"),
        Path("src/probe.rs"),
        Path("src/loader_child.rs"),
        Path("src/boundary_child.rs"),
        Path("patches/mxc-strict-windows-psec.patch"),
        Path("patches/mxc-literal-argv.patch"),
        Path("patches/mxc-windows-literal-argv.patch"),
    ]
    for relative in files:
        target = artifact / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for binary in (BINARY, LOADER_BINARY, BOUNDARY_BINARY):
        shutil.copyfile(ROOT / "target" / "release" / binary, artifact / "bin" / binary)
        (artifact / "bin" / binary).chmod(0o755)
    (artifact / "upstream").mkdir()
    for name, source, lock_path, license_name in [
        ("axis", axis, axis / "Cargo.lock", "LICENSE"),
        ("mxc", mxc, mxc / "src" / "Cargo.lock", "LICENSE.md"),
    ]:
        shutil.copyfile(lock_path, artifact / "upstream" / f"{name}-Cargo.lock")
        shutil.copyfile(source / license_name, artifact / "upstream" / f"{name}-LICENSE")
    (artifact / "TOOLCHAIN.txt").write_text(toolchain + "\n" + cargo_version + "\n", encoding="utf-8")
    provenance = {
        "schema": "defenseclaw-contributor-axis-windows-psec-v1",
        "variant": "standalone_std_boundary_literal_argv",
        "axis_commit": AXIS_COMMIT,
        "mxc_commit": MXC_COMMIT,
        "mxc_patch_sha256": digest(PATCH),
        "mxc_literal_argv_patch_sha256": digest(LITERAL_PATCH),
        "mxc_literal_argv_patch_source": LITERAL_PATCH_SOURCE,
        "mxc_windows_argv_patch_sha256": digest(WINDOWS_ARGV_PATCH),
        "mxc_patched_paths": sorted(PATCHED_PATHS),
        "mxc_added_paths": sorted(ADDED_PATHS),
        "mxc_overlay_file_sha256": overlay_before,
        "combined_lock_sha256": lock_before,
        "upstream_lock_sha256": upstream_locks,
        "build_mode": args.mode,
        "probe_executed": False,
        "pure_private_environment_spelling_test_passed": True,
        "human_lock_review_required_before_live_execution": True,
        "locked_rebuild": args.mode == "build-locked",
        "scope": "fixed_windows_native_psec_boundary_literal_argv",
        "production_certification": False,
        "files": {
            path.relative_to(artifact).as_posix(): digest(path)
            for path in sorted(artifact.rglob("*"))
            if path.is_file()
        },
    }
    (artifact / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print("Contributor build complete; probe was not executed.")
    if args.mode == "generate-lock":
        print(
            "Review and commit source/Cargo.lock, then rebuild from fresh sources "
            "in build-locked mode before any live execution."
        )


if __name__ == "__main__":
    main()
