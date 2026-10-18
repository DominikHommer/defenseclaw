#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Bound one verified fixed PSEC probe through the reviewed owned-Job wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import threading
import time
from pathlib import Path

import verify_live_artifact as artifact_verifier

OUTPUT_BOUND = 1024 * 1024
CHECKS = {
    "separate_std_loader_marker",
    "exit23",
    "retained_direct_process_handles_signaled",
    "owned_fixture_removed",
}


def valid_observations(record: object, receipt: dict) -> bool:
    if not isinstance(record, dict):
        return False
    if not {"binary_sha256", "build_commit", "build_run", "combined_lock_sha256", "artifact_id"} <= receipt.keys():
        return False
    if any(
        record.get(name) != value or type(record.get(name)) is not type(value)
        for name, value in {
            "passed": True,
            "production_certification": False,
            "scope": artifact_verifier.SCOPE,
            "variant": artifact_verifier.VARIANT,
            "mode": "loader-only",
            "exit_code": 0,
            "outer_job_active_before_final_cleanup": 0,
            "outer_job_empty": True,
            "assigned_before_resume": True,
            "binary_sha256": receipt["binary_sha256"],
            "build_commit": receipt["build_commit"],
            "build_run": receipt["build_run"],
            "combined_lock_sha256": receipt["combined_lock_sha256"],
            "artifact_id": receipt["artifact_id"],
        }.items()
    ):
        return False
    try:
        lines = [json.loads(line) for line in record["stdout"].splitlines() if line]
    except (KeyError, ValueError, TypeError, AttributeError):
        return False
    if len(lines) != 2 or not all(isinstance(line, dict) for line in lines):
        return False
    observation = lines[0]
    if observation.get("direct_handle_signaled") is not True or observation != {
        "case": "loader",
        "outcome": "Exited(23)",
        "direct_handle_signaled": True,
        "stdout": "FIXED_PSEC_LOADER_STARTED\n",
        "stderr": "",
    }:
        return False
    final = lines[1]
    return (
        final.get("axis_commit") == artifact_verifier.AXIS_COMMIT
        and final.get("mxc_commit") == artifact_verifier.MXC_COMMIT
        and final.get("translation_contract") == "fixed-axis-hard-block-to-mxc-typed-1.0.0"
        and final.get("backend") == "native_windows_psec_only"
        and final.get("production_qualification") is False
        and final.get("loader_only_diagnostic") is True
        and isinstance(final.get("checks"), list)
        and all(isinstance(check, str) for check in final["checks"])
        and len(final["checks"]) == len(CHECKS)
        and set(final["checks"]) == CHECKS
    )


class Capture:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.data = bytearray()
        self.overflow = False
        self.error: str | None = None

    def drain(self, source) -> None:
        try:
            while chunk := source.read(4096):
                with self.lock:
                    if len(self.data) + len(chunk) <= OUTPUT_BOUND:
                        self.data.extend(chunk)
                    else:
                        self.overflow = True
        except OSError as error:
            with self.lock:
                self.error = type(error).__name__

    def snapshot(self) -> tuple[bytes, bool, str | None]:
        with self.lock:
            return bytes(self.data), self.overflow, self.error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loader-only", action="store_true", required=True)
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--custody-sha256", type=artifact_verifier.digest_argument, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--receipt-sha256", type=artifact_verifier.digest_argument, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("live probe requires native Windows x86_64")
    custody = args.custody.absolute()
    receipt_path = args.receipt.absolute()
    if hashlib.sha256(artifact_verifier.ordinary_file(custody)).hexdigest() != args.custody_sha256:
        raise ValueError("the explicitly pinned contributor custody binary differs")
    receipt_raw = artifact_verifier.ordinary_file(receipt_path, 64 * 1024)
    if hashlib.sha256(receipt_raw).hexdigest() != args.receipt_sha256:
        raise ValueError("the independently pinned verification receipt differs")
    receipt = json.loads(receipt_raw)
    if (
        not isinstance(receipt, dict)
        or receipt.get("verified") is not True
        or receipt.get("execution_performed") is not False
        or receipt.get("variant") != artifact_verifier.VARIANT
        or receipt.get("scope") != artifact_verifier.SCOPE
    ):
        raise ValueError("an independently verified non-executing receipt is required")
    evidence = args.evidence.absolute()
    evidence.mkdir(mode=0o700)
    for name in ("wrapper-home", "wrapper-tmp"):
        (evidence / name).mkdir(mode=0o700)
    system = os.environ.get("SYSTEMROOT", "")
    if not Path(system).is_absolute():
        raise ValueError("native Windows system directory is missing")
    environment = {
        "SYSTEMROOT": system,
        "WINDIR": system,
        "HOME": str(evidence / "wrapper-home"),
        "USERPROFILE": str(evidence / "wrapper-home"),
        "TEMP": str(evidence / "wrapper-tmp"),
        "TMP": str(evidence / "wrapper-tmp"),
    }
    command = [
        str(custody),
        "-loader-only",
        "-receipt",
        str(receipt_path),
        "-receipt-sha256",
        args.receipt_sha256,
        "-case-root",
        str(evidence / "psec-headless-01"),
    ]
    output, diagnostic = Capture(), Capture()
    started = time.monotonic()
    deadline = False
    errors = []
    exit_code = None
    process = None
    readers = []
    try:
        process = subprocess.Popen(
            command,
            cwd=evidence,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            bufsize=0,
        )
        assert process.stdout is not None and process.stderr is not None
        for capture, stream in [(output, process.stdout), (diagnostic, process.stderr)]:
            reader = threading.Thread(target=capture.drain, args=(stream,), daemon=True)
            reader.start()
            readers.append(reader)
        try:
            exit_code = process.wait(timeout=55)
        except subprocess.TimeoutExpired:
            deadline = True
            # This Popen retains the exact helper process handle. Killing it
            # closes its non-inherited Job handle; never signal an inferred PID.
            process.kill()
            exit_code = process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError) as error:
        errors.append(type(error).__name__)
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                errors.append("owned custody handle did not stop")
    finally:
        for reader in readers:
            reader.join(timeout=2)
            if reader.is_alive():
                errors.append("bounded custody reader did not stop")
        if process is not None:
            for stream, reader in zip((process.stdout, process.stderr), readers, strict=False):
                # Do not block closing a stream concurrently owned by a stuck
                # reader. That path is a failed qualification, with daemon
                # readers and handles reclaimed when this CLI process exits.
                if stream is not None and not reader.is_alive():
                    stream.close()
    output_bytes, output_overflow, output_error = output.snapshot()
    diagnostic_bytes, diagnostic_overflow, diagnostic_error = diagnostic.snapshot()
    for name, data in [("custody-stdout.json", output_bytes), ("custody-stderr.txt", diagnostic_bytes)]:
        with (evidence / name).open("xb") as destination:
            destination.write(data)
    result = None
    try:
        result = json.loads(output_bytes)
    except (ValueError, UnicodeDecodeError):
        errors.append("custody JSON missing or invalid")
    fixtures = sorted(str(path) for path in (evidence / "psec-headless-01" / "tmp").glob("dc-axis-windows-psec-*"))
    passed = (
        not errors
        and not deadline
        and exit_code == 0
        and not output_overflow
        and not diagnostic_overflow
        and output_error is None
        and diagnostic_error is None
        and not fixtures
        and valid_observations(result, receipt)
    )
    record = {
        "passed": passed,
        "command": command,
        "exit_code": exit_code,
        "errors": errors,
        "outer_deadline": deadline,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "custody_sha256": args.custody_sha256,
        "receipt_sha256": args.receipt_sha256,
        "output_overflow": output_overflow or diagnostic_overflow,
        "output_read_errors": [output_error, diagnostic_error],
        "retained_owned_fixtures": fixtures,
        "observations": result,
        "production_or_claude_qualification": False,
        "scope": (
            "fixed std-only loader diagnostic; marker, exit23 and owned custody only; "
            "no filesystem/network boundary, terminal, proxy, secrets, model or general resource audit"
        ),
    }
    with (evidence / "live-result.json").open("x", encoding="utf-8") as destination:
        destination.write(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
