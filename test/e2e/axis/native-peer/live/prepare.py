# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Prepare only exact reviewed fixed-canary artifacts; never execute images."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[5] / "internal/axis/native"))
from artifact_archive import ZipEvidence, json_object, ordinary, sha  # noqa: E402
from verify_native_artifact import manifest as peer_manifest  # noqa: E402
from verify_native_artifact import record_matches, static_elf

REPOSITORY = "cisco-ai-defense/defenseclaw"
RECEIPT_SHA = "9e7c6f82be689db0167067b0eb108f48870279e4a015c1b91604583b063e02db"
# Independently reviewed source/build/image inputs; no caller or API chooses a
# pin. This source recipe needs its own review and explicit run authorization.
DRIVER_PROVENANCE_SHA = "7d0263acee3423f218015e0698f9c374aaed212728ffb7f7103e4fdd5b0fe71f"
PINS = {
    "peer": {
        "commit": "aa21514cf1a1ce7c17ddd4a06d76efc001c7d5d7",
        "run": 39148188923,
        "artifact": 12144198239,
        "archive": "14752d1506e9f206b5f2c0c5f227efe0fdccee5594530e9e0b7e3b06ba5405a3",
        "provenance": "2223dd9576928daabfa41288c38810568215faf000cd161ec2a5bbf680d6a3e3",
        "workflow": ".github/workflows/axis-native-peer-build.yml",
        "stem": "axis-private-native-peer-linux-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "push",
    },
    "payload": {
        "commit": "d07485c4cc8ecf8ab7db1a0121ac61a6a8b636f3",
        "run": 39134453264,
        "artifact": 12138953410,
        "archive": "251779fc9462ca8f49014dceb6c86b633c86712b488d009a4a61e9095df9c401",
        "provenance": "ae7d3700b3a8f20236cbef90e249f2c529103747e79d8c3473042b9fd5259a98",
        "workflow": ".github/workflows/axis-native-payload-build.yml",
        "stem": "axis-fixed-native-payload-linux-",
        "branch": "codex/axis-peer-experiments",
        "event": "push",
    },
    "wrapper": {
        "commit": "efc2c3b304690320447dee57f01a51fc6df25060",
        "run": 39150168377,
        "artifact": 12144044675,
        "archive": "038fcd824a661d4ab81ccdc8b29ef3201cc47453f8b657ac7753750002084fc2",
        "provenance": "46e190705132b0e1098e37ee84af2ab775fc0f92a581c4411c822f7ebc19b2d7",
        "workflow": ".github/workflows/axis-native-harness-build.yml",
        "stem": "axis-reviewed-native-harness-linux-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "workflow_dispatch",
    },
    "driver": {
        "commit": "74290890763d4a049d9b343e0f25240a03fae496",
        "run": 39150939990,
        "artifact": 12144563368,
        "archive": "d9d256f1587a3659d0d0ac689b28ffa3e98e62da2c3d623d6e01adc5dea9138e",
        "workflow": ".github/workflows/axis-native-driver-build.yml",
        "stem": "axis-fixed-native-outer-driver-linux-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "workflow_dispatch",
    },
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(argv, bound=128 << 20):
    # Trusted host GH only. This read-only Actions token remains in host metadata
    # processes and is never placed in prepared images or the driver's env.
    env = {
        key: os.environ[key]
        for key in (
            "PATH",
            "HOME",
            "SYSTEMROOT",
            "WINDIR",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "GH_TOKEN",
            "GITHUB_TOKEN",
        )
        if key in os.environ
    }
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    captured, failed = {}, threading.Event()

    def drain(label, stream, limit):
        try:
            captured[label] = stream.read(limit + 1)
            if len(captured[label]) > limit:
                failed.set()
        except Exception:
            failed.set()

    readers = [
        threading.Thread(target=drain, args=(label, stream, limit), daemon=True)
        for label, stream, limit in [("stdout", process.stdout, bound), ("stderr", process.stderr, 64 << 10)]
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + 60
    try:
        while process.poll() is None and not failed.is_set() and time.monotonic() < deadline:
            failed.wait(0.01)
        require(time.monotonic() < deadline, "metadata operation deadline")
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
            raise ValueError("metadata output bound")
        for reader in readers:
            reader.join(timeout=2)
        require(
            not failed.is_set() and all(not reader.is_alive() for reader in readers) and process.returncode == 0,
            "metadata operation refused",
        )
        return captured["stdout"]
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for reader, stream in zip(readers, (process.stdout, process.stderr), strict=True):
            if not reader.is_alive():
                stream.close()


def api(path):
    return json_object(command(["gh", "api", f"repos/{REPOSITORY}/{path}"], 1 << 20))


def mapping(value, key):
    result = value.get(key)
    require(isinstance(result, dict), "metadata object differs")
    return result


def check_actions(pin, run, artifact):
    require(
        run.get("id") == pin["run"] and run.get("run_attempt") == 1 and run.get("head_sha") == pin["commit"],
        "run identity differs",
    )
    require(
        mapping(run, "repository").get("full_name") == REPOSITORY
        and mapping(run, "head_repository").get("full_name") == REPOSITORY,
        "foreign source",
    )
    require(
        run.get("status") == "completed" and run.get("conclusion") == "success" and run.get("path") == pin["workflow"],
        "build did not succeed",
    )
    require(run.get("head_branch") == pin["branch"] and run.get("event") == pin["event"], "build route differs")
    require(
        artifact.get("id") == pin["artifact"]
        and artifact.get("expired") is False
        and artifact.get("digest") == "sha256:" + pin["archive"],
        "artifact identity differs",
    )
    require(artifact.get("name") == pin["stem"] + pin["commit"], "artifact name differs")
    require(
        mapping(artifact, "workflow_run").get("id") == pin["run"]
        and mapping(artifact, "workflow_run").get("head_sha") == pin["commit"],
        "artifact source differs",
    )
    require(
        type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= 128 << 20,
        "artifact size differs",
    )


def flat_manifest(archive, pin):
    raw = archive.read("PROVENANCE.json")
    require(sha(raw) == pin["provenance"], "external provenance pin differs")
    value = json_object(raw)
    require(
        value.get("repository") == REPOSITORY
        and value.get("workflow") == pin["workflow"]
        and value.get("build_commit") == pin["commit"]
        and value.get("run_id") == pin["run"]
        and value.get("run_attempt") == 1,
        "provenance run differs",
    )
    files = value.get("files")
    require(
        isinstance(files, dict) and set(archive.files) == set(files) | {"PROVENANCE.json"},
        "complete file manifest differs",
    )
    for name, record in files.items():
        record_matches(archive.read(name), record)
    return raw


def select(archive, member, digest, size=None):
    raw = archive.read(member)
    require(sha(raw) == digest and (size is None or len(raw) == size), "fixed member differs")
    return raw


def prepare(root, metadata_api=api, download=None):
    require(
        isinstance(DRIVER_PROVENANCE_SHA, str) and re.fullmatch("[0-9a-f]{64}", DRIVER_PROVENANCE_SHA),
        "driver artifact admission is closed",
    )
    require(download is not None, "fixed download primitive required")
    receipt = ordinary(Path(__file__).with_name("REVIEWED-ARTIFACTS.json"), 64 << 10)
    require(sha(receipt) == RECEIPT_SHA, "combined receipt source differs")
    root.mkdir(mode=0o700)
    evidence = root / "preparation-evidence"
    evidence.mkdir(mode=0o700)
    images, proofs, source = root / "images", root / "proofs", root / "source"
    for directory in (images, proofs, source):
        directory.mkdir(mode=0o700)
    (root / "REVIEWED-ARTIFACTS.json").write_bytes(receipt)
    archives = {}
    for role, original in PINS.items():
        pin = dict(original)
        if role == "driver":
            pin["provenance"] = DRIVER_PROVENANCE_SHA
        run, artifact = (
            metadata_api(f"actions/runs/{pin['run']}/attempts/1"),
            metadata_api(f"actions/artifacts/{pin['artifact']}"),
        )
        check_actions(pin, run, artifact)
        raw = download(pin["artifact"])
        require(len(raw) == artifact["size_in_bytes"] and sha(raw) == pin["archive"], "archive bytes differ")
        archive = ZipEvidence(raw)
        if role == "peer":
            peer_manifest(archive, pin["provenance"])
        else:
            flat_manifest(archive, pin)
        for label, value in [("run", run), ("artifact", artifact)]:
            (evidence / (role + "-" + label + ".json")).write_text(json.dumps(value, indent=2) + "\n")
        archives[role] = archive
    members = [
        (
            "peer",
            "build-artifact/bin/defenseclaw-axis-peer",
            images / "peer",
            "274717415360304d4ff14096faa13cc98fcf7eaba5409dcd1c800350d4048665",
            2722752,
        ),
        (
            "peer",
            "build-artifact/static/bwrap-static-musl-repeat-a",
            images / "bwrap-static-musl",
            "da4b55953dbc5843e712edf8f1603637926cfb1cd64e6fcb9a69d914b347e9e9",
            194488,
        ),
        (
            "payload",
            "bin/payload",
            images / "fixed-payload",
            "d2d2ac02859541bbc03eaae305a8b1f833338a7783f8b31e57046e5dd4e4533c",
            1929342,
        ),
        (
            "wrapper",
            "bin/reviewed-harness",
            images / "reviewed-wrapper",
            "cd72428ee90356d4a9febe41bc8a131386c92dff43ad07871d74ec9763085233",
            3432574,
        ),
        (
            "driver",
            "bin/fixed-outer-driver",
            images / "fixed-driver",
            "a82943121c4d69f35a8612d3bd30dcf59ae66dc86bbb745cc52e5f52d835a357",
            3182718,
        ),
    ]
    for role, member, target, digest, size in members:
        raw = select(archives[role], member, digest, size)
        if role != "peer" or target.name == "bwrap-static-musl":
            static_elf(raw)
        target.write_bytes(raw)
        target.chmod(0o500)
    for role, member, target, digest in [
        (
            "peer",
            "build-artifact/static/STATIC-CLOSURE.json",
            proofs / "STATIC-CLOSURE.json",
            "a28d984758b82397f371e4b7bb785d274005404d2546d606e2319dc0aaf33e56",
        ),
        ("peer", "build-artifact/PROVENANCE.json", proofs / "peer-PROVENANCE.json", PINS["peer"]["provenance"]),
        ("payload", "PROVENANCE.json", proofs / "payload-PROVENANCE.json", PINS["payload"]["provenance"]),
        (
            "payload",
            "source/test/e2e/axis/native-peer/payload/main_linux.go",
            source / "payload-main_linux.go",
            "40e6e1bccb635385cdab82e0969de893cb9e5c9d1aeb1499a2446623a9cca986",
        ),
    ]:
        target.write_bytes(select(archives[role], member, digest))
    for role in ("wrapper", "driver"):
        (evidence / (role + "-PROVENANCE.json")).write_bytes(archives[role].read("PROVENANCE.json"))
    record = {
        "scope": "fixed_linux_native_peer_input_preparation",
        "execution_performed": False,
        "production_certification": False,
        "full_upstream_review_repeated": False,
        "admission_basis": "exact_previously_dual_reviewed_archive_and_provenance_pins",
        "receipt_sha256": RECEIPT_SHA,
        "images": {
            path.name: {"sha256": sha(ordinary(path)), "size": path.stat().st_size} for path in sorted(images.iterdir())
        },
    }
    (evidence / "PREPARATION.json").write_text(json.dumps(record, indent=2) + "\n")


def main():
    require(
        os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "fixed disposable CI preparation only",
    )
    if sys.argv[1:] == ["--collect-fixed-evidence"]:
        collect()
        return
    require(len(sys.argv) == 1, "fixed preparation selector only")
    prepare(
        Path("live-inputs"),
        download=lambda artifact: command(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact}/zip"]),
    )


def collect():
    evidence = Path("live-evidence")
    evidence.mkdir(mode=0o700, exist_ok=True)
    record = {
        "scope": "fixed_linux_native_peer_evidence_collection",
        "fixture_copied": False,
        "production_certification": False,
    }
    try:
        result = json_object(ordinary(evidence / "DRIVER-RESULT.json", 1 << 20))
        require(
            result.get("scope") == "fixed_linux_native_peer_outer_driver_v1"
            and result.get("whole_wrapper_namespace_cleanup_observed") is True
            and result.get("pending_driver_cleanup") == 0,
            "whole-wrapper cleanup not observed",
        )
        nested = result.get("wrapper_record")
        if not isinstance(nested, dict):
            raw = result.get("wrapper_stdout", "")
            require(isinstance(raw, str) and len(raw.encode()) <= 64 << 10, "fixed raw wrapper output differs")
            nested = json_object(raw.encode())
        require(
            nested.get("scope") == "fixed_linux_native_peer_offline_contributor_v1"
            and nested.get("production_certification") is False,
            "fixed nested result differs",
        )
        fixture = nested.get("synthetic_fixture")
        if fixture is None:
            return
        require(nested.get("artifact_receipt_sha256") == RECEIPT_SHA, "fixed nested receipt differs")
        require(
            isinstance(fixture, str) and re.fullmatch("/tmp/dc-axis-native-peer-[0-9a-f]{32}", fixture),
            "fixed fixture identity differs",
        )
        root = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(root)
            require(
                metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700, "fixture ownership differs"
            )
            destination = evidence / "synthetic-fixture"
            destination.mkdir(mode=0o700)
            budget = [0, 0]
            copy_fixture(root, destination, 0, budget)
            record["fixture_copied"], record["members"], record["bytes"] = True, budget[0], budget[1]
        finally:
            os.close(root)
    except (ValueError, OSError):
        record["error"] = "fixed_failure_evidence_not_fully_copied"
    finally:
        (evidence / "COLLECTION.json").write_text(json.dumps(record, indent=2) + "\n")


def copy_fixture(parent, destination, depth, budget):
    require(depth <= 3, "fixture depth bound")
    names = os.listdir(parent)
    require(len(names) <= 32, "fixture member bound")
    for name in sorted(names):
        require(re.fullmatch("[a-z0-9-]{1,64}", name), "fixture member name differs")
        budget[0] += 1
        require(budget[0] <= 32, "fixture total member bound")
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            metadata = os.fstat(child)
            require(metadata.st_uid == os.geteuid(), "fixture member owner differs")
            target = destination / name
            if stat.S_ISDIR(metadata.st_mode):
                target.mkdir(mode=0o700)
                copy_fixture(child, target, depth + 1, budget)
            else:
                require(
                    stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= 64 << 10,
                    "fixture file type or size differs",
                )
                with os.fdopen(os.dup(child), "rb") as stream:
                    raw = stream.read((64 << 10) + 1)
                require(len(raw) == metadata.st_size, "fixture file changed")
                budget[1] += len(raw)
                require(budget[1] <= 1 << 20, "fixture total byte bound")
                target.write_bytes(raw)
                target.chmod(0o600)
        finally:
            os.close(child)


if __name__ == "__main__":
    main()
