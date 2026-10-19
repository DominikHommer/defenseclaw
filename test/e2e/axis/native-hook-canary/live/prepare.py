#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Prepare only externally pinned contained-hook images. Never execute them."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[5] / "internal/axis/native"))
from artifact_archive import ZipEvidence, json_object, sha  # noqa: E402
from verify_native_artifact import manifest as peer_manifest  # noqa: E402
from verify_native_artifact import static_elf  # noqa: E402

REPOSITORY = "cisco-ai-defense/defenseclaw"
BRANCH = "codex/axis-sandbox-feasibility"
REF = "refs/heads/" + BRANCH
SOURCE_CANARY = "b410fd72fa172a8d3c0ee6c10ffe2d6221f023ec"
SOURCE_WRAPPER = "48f65a1205675109cabb6346107e593a931c365a"
PINS = {
    "peer": {
        "source": "36139fb98708b4cc021d1f20841ace231e058fa2",
        "run": 39204276069,
        "artifact": 12165009428,
        "archive": "b44a125c83d0e0eab9bed64a706ae1c5ce4850e153076c921d2a6b58ef013037",
        "provenance": "83aedefbd8a6abe462719b46113ac3b02f3e34232acf6ae4f61816a1da4dc287",
        "workflow": ".github/workflows/axis-native-peer-build.yml",
        "name": "axis-private-native-peer-linux-36139fb98708b4cc021d1f20841ace231e058fa2",
        "event": "push",
    },
    "canary": {
        "source": SOURCE_CANARY,
        "run": 39300548829,
        "artifact": 12212382202,
        "archive": "7a9d9fb9817ddc3ae38d258ba7b69bca47a826d39bad0516e7c7b7583ed8f762",
        "provenance": "1a50bae406026c492e94edd7c3fa2443bbca46675f6d5900b966409a7cb7411e",
        "workflow": ".github/workflows/axis-contained-hook-canary-build.yml",
        "name": "axis-contained-hook-build-only-b410fd72fa172a8d3c0ee6c10ffe2d6221f023ec",
        "event": "workflow_dispatch",
    },
    "wrapper": {
        "source": SOURCE_WRAPPER,
        "run": 39303696862,
        "artifact": 12211184405,
        "archive": "a1f5427f456760b3c0ac8b93d016f9c0286fbea2e3b74c0bf56d2999c9860fa6",
        "provenance": "df3d53b9cd348d03d353b3196dfe814a0e1e082a94e63af35aaaae27b3c5c9c7",
        "workflow": ".github/workflows/axis-contained-hook-live-wrapper-build.yml",
        "name": "axis-contained-hook-outer-build-only-48f65a1205675109cabb6346107e593a931c365a",
        "event": "workflow_dispatch",
    },
}
IMAGES = {
    "peer": (
        "peer",
        "build-artifact/bin/defenseclaw-axis-peer",
        "native-hook-canary-inputs/peer",
        "e2afdf64b0456817f469eb3a7acf3eceb43bc204187a194f3c5e8d54a68c3e3c",
        2760048,
        0o400,
    ),
    "bubblewrap": (
        "peer",
        "build-artifact/static/bwrap-static-musl-repeat-a",
        "native-hook-canary-inputs/bubblewrap",
        "b4d1a59426c6a52e9f9a0d57d03d620e4dfc1beef976201a3afc0c1b492ee37d",
        198584,
        0o400,
    ),
    "payload": (
        "canary",
        "fixed-hook-payload",
        "native-hook-canary-inputs/payload",
        "d1a812ce303b8eec3ba1dd9330ea5e338e1a413b41c2924ae060f68fc1144046",
        11247742,
        0o400,
    ),
    "testdriver": (
        "canary",
        "fixed-contained-hook-driver.test",
        "fixed-contained-hook-driver.test",
        "30d69276f09dd416b3fa224adf8a3512a5058317173c3309d20c0b2a73cfdb51",
        141721726,
        0o500,
    ),
    "wrapper": (
        "wrapper",
        "fixed-contained-hook-outer",
        "fixed-contained-hook-outer",
        "9cb6b45ff73d2caf0211c6a52d8aa5221cc3618fda5ed594eba035cb54fe45a5",
        2936958,
        0o500,
    ),
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha64(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def closed_admission():
    require(re.fullmatch(r"[0-9a-f]{40}", SOURCE_CANARY or "") is not None, "canary source pin closed")
    require(re.fullmatch(r"[0-9a-f]{40}", SOURCE_WRAPPER or "") is not None, "wrapper source pin closed")
    for pin in PINS.values():
        require(re.fullmatch(r"[0-9a-f]{40}", pin["source"] or "") is not None, "source admission closed")
        require(
            type(pin["run"]) is int and pin["run"] > 0 and type(pin["artifact"]) is int and pin["artifact"] > 0,
            "run admission closed",
        )
        require(sha64(pin["archive"]) and sha64(pin["provenance"]) and pin["name"], "archive admission closed")
    for _, _, _, digest, size, _ in IMAGES.values():
        require(sha64(digest) and type(size) is int and 64 <= size <= 256 << 20, "image admission closed")
    require(IMAGES["payload"][3] == _wrapper_source_payload_pin(), "wrapper/payload source pin differs")
    require(IMAGES["testdriver"][3] == _wrapper_source_driver_pin(), "wrapper/driver source pin differs")
    require(IMAGES["payload"][4] == _wrapper_source_payload_size(), "wrapper/payload size pin differs")
    require(IMAGES["testdriver"][4] == _wrapper_source_driver_size(), "wrapper/driver size pin differs")


def _wrapper_source():
    # Admission checks source literals, never a runtime receipt hash authority.
    return (Path(__file__).with_name("main_linux.go")).read_text(encoding="utf-8")


def _literal(name):
    found = re.findall(rf'^const {name} = "([0-9a-f]*)"$', _wrapper_source(), re.MULTILINE)
    require(len(found) == 1, "wrapper source literal differs")
    return found[0]


def _size_literal(name):
    found = re.findall(rf"^const {name} int64 = ([0-9]+)$", _wrapper_source(), re.MULTILINE)
    require(len(found) == 1, "wrapper size literal differs")
    return int(found[0])


def _wrapper_source_payload_pin():
    return _literal("payloadSHA")


def _wrapper_source_driver_pin():
    return _literal("testDriverSHA")


def _wrapper_source_payload_size():
    return _size_literal("payloadSize")


def _wrapper_source_driver_size():
    return _size_literal("testDriverSize")


def command(argv, bound=128 << 20):
    env = {name: os.environ[name] for name in ("PATH", "HOME", "GH_TOKEN") if name in os.environ}
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    values, overflow = {}, threading.Event()

    def drain(name, stream, limit):
        try:
            values[name] = stream.read(limit + 1)
            if len(values[name]) > limit:
                overflow.set()
        except OSError:
            overflow.set()

    readers = [
        threading.Thread(target=drain, args=(name, stream, limit), daemon=True)
        for name, stream, limit in (("out", child.stdout, bound), ("err", child.stderr, 1 << 16))
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + 90
    try:
        while child.poll() is None and not overflow.is_set() and time.monotonic() < deadline:
            overflow.wait(0.02)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
            raise ValueError("fixed Actions metadata/download bound")
        for reader in readers:
            reader.join(timeout=2)
        require(
            child.returncode == 0 and not overflow.is_set() and all(not r.is_alive() for r in readers),
            "fixed Actions metadata/download failed",
        )
        return values["out"]
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def api(path, bound=1 << 20):
    return command(["gh", "api", f"repos/{REPOSITORY}/{path}"], bound)


def check_actions(pin):
    run = json_object(api(f"actions/runs/{pin['run']}/attempts/1"))
    artifact = json_object(api(f"actions/artifacts/{pin['artifact']}"))
    require(
        run.get("id") == pin["run"] and run.get("run_attempt") == 1 and run.get("head_sha") == pin["source"],
        "exact run identity differs",
    )
    require(
        run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("path") == pin["workflow"]
        and run.get("event") == pin["event"]
        and run.get("head_branch") == BRANCH,
        "fixed build route differs",
    )
    require(
        run.get("repository", {}).get("full_name") == REPOSITORY
        and run.get("head_repository", {}).get("full_name") == REPOSITORY,
        "foreign source route",
    )
    require(
        artifact.get("id") == pin["artifact"]
        and artifact.get("expired") is False
        and artifact.get("name") == pin["name"]
        and artifact.get("digest") == "sha256:" + pin["archive"],
        "fixed artifact identity differs",
    )
    require(
        artifact.get("workflow_run", {}).get("id") == pin["run"]
        and artifact.get("workflow_run", {}).get("head_sha") == pin["source"]
        and type(artifact.get("size_in_bytes")) is int
        and 0 < artifact["size_in_bytes"] <= 128 << 20,
        "fixed artifact route/size differs",
    )
    return run, artifact


def flat_manifest(archive, pin, role):
    raw = archive.read("PROVENANCE.json", 4 << 20)
    require(sha(raw) == pin["provenance"], "fixed external provenance pin differs")
    value = json_object(raw)
    require(
        value.get("source") == pin["source"] and set(value) == {"source", "files"},
        "fixed provenance source/schema differs",
    )
    files = value["files"]
    require(
        isinstance(files, dict) and set(archive.files) == set(files) | {"PROVENANCE.json"},
        "fixed provenance inventory differs",
    )
    for name, entry in files.items():
        require(isinstance(entry, dict) and set(entry) == {"sha256", "bytes"}, "fixed provenance member schema differs")
        if role == "canary" and name == "fixed-contained-hook-driver.test":
            data = archive.read(name, IMAGES["testdriver"][4])
        else:
            data = archive.read(name)
        require(entry == {"sha256": sha(data), "bytes": len(data)}, "fixed provenance member bytes differ")
    if role == "canary":
        result = json_object(archive.read("BUILD-RESULT.json", 1 << 20))
        require(
            result.get("source") == pin["source"]
            and result.get("native_execution") is False
            and result.get("production_qualification") is False
            and result.get("peer_acquisition") is False,
            "canary build-only boundary differs",
        )
        require(
            result.get("generated_payload_sha256") == IMAGES["payload"][3]
            and result.get("payload_bytes") == IMAGES["payload"][4],
            "generated payload differs",
        )
        require(
            result.get("driver_sha256") == IMAGES["testdriver"][3]
            and result.get("driver_bytes") == IMAGES["testdriver"][4],
            "compiled testdriver differs",
        )
    if role == "wrapper":
        result = json_object(archive.read("BUILD-RESULT.json", 1 << 20))
        require(
            result.get("source") == pin["source"]
            and result.get("native_execution") is False
            and result.get("production_qualification") is False,
            "outer build-only boundary differs",
        )
        require(
            result.get("wrapper_sha256") == IMAGES["wrapper"][3]
            and result.get("wrapper_bytes") == IMAGES["wrapper"][4],
            "outer image differs",
        )
        require(
            archive.read("sources/main_linux.go") == Path(__file__).with_name("main_linux.go").read_bytes(),
            "outer source differs from reviewed running workflow",
        )
    return value


def prepare():
    require(
        sys.platform == "linux"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_REF") == REF
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
        "fixed disposable hosted runner required",
    )
    require(
        os.geteuid() != 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid(), "fixed nonroot host required"
    )
    require(len(sys.argv) == 1, "no runtime preparation selector")
    closed_admission()  # before metadata/network/filesystem reads
    require(
        command(["git", "rev-parse", "HEAD"], 128).decode().strip() == os.environ.get("GITHUB_SHA"),
        "exact checkout differs",
    )
    require(not command(["git", "status", "--porcelain"], 4096), "dirty checkout refused")
    archives, metadata = {}, {}
    for role, pin in PINS.items():
        run, artifact = check_actions(pin)
        raw = api(f"actions/artifacts/{pin['artifact']}/zip", 128 << 20)
        require(len(raw) == artifact["size_in_bytes"] and sha(raw) == pin["archive"], "fixed ZIP bytes differ")
        if role == "canary":
            archive = ZipEvidence(raw, member_bounds={"fixed-contained-hook-driver.test": IMAGES["testdriver"][4]})
        else:
            archive = ZipEvidence(raw)
        if role == "peer":
            peer_manifest(archive, pin["provenance"])
        else:
            flat_manifest(archive, pin, role)
        archives[role] = archive
        metadata[role] = {"run": run, "artifact": artifact}
    images = {}
    for label, (role, member, _, digest, size, _) in IMAGES.items():
        if label == "testdriver":
            require(
                role == "canary" and member == "fixed-contained-hook-driver.test", "fixed large driver mapping differs"
            )
            raw = archives[role].read(member, size)
        else:
            raw = archives[role].read(member)
        require(len(raw) == size and sha(raw) == digest, "fixed image bytes differ")
        # The exact reviewed Rust peer is glibc-linked ET_DYN. Its archive
        # provenance and image digest are fixed; all other images are static.
        if label != "peer":
            static_elf(raw)
        images[label] = raw
    root = Path("live-inputs")
    root.mkdir(mode=0o700)
    child = root / "native-hook-canary-inputs"
    child.mkdir(mode=0o700)
    for label, (_, _, relative, _, _, mode) in IMAGES.items():
        target = root / relative
        with target.open("xb") as out:
            out.write(images[label])
        target.chmod(mode)
    evidence = root / "preparation-evidence"
    evidence.mkdir(mode=0o700)
    for role, records in metadata.items():
        for kind, value in records.items():
            (evidence / f"{role}-{kind}.json").write_text(
                json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
    summary = {
        "scope": "fixed_contained_hook_live_input_preparation",
        "native_execution": False,
        "production_qualification": False,
        "images": {label: {"sha256": sha(raw), "bytes": len(raw)} for label, raw in images.items()},
    }
    (evidence / "PREPARATION.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        prepare()
    except (ValueError, OSError, subprocess.SubprocessError):
        print("fixed contained-hook image preparation refused", file=sys.stderr)
        raise SystemExit(1) from None
