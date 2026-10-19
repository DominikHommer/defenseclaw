#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Closed source/test/build recipe. Never runs either produced image."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class RefusedError(Exception):
    pass


TAG = "axis_native_contained_hook_canary"
PIN = "internal/gateway/native_sandbox_hook_contained_pin_linux_test.go"
PREFIX = "test/e2e/axis/native-hook-canary/"
REPOSITORY = "cisco-ai-defense/defenseclaw"
REF = "refs/heads/codex/axis-sandbox-feasibility"
CONNECTORS = (
    "amp",
    "antigravity",
    "claudecode",
    "codex",
    "copilot",
    "cursor",
    "devin",
    "hermes",
    "kiro",
    "omnigent",
    "opencode",
    "openhands",
)
SAFE_TESTS = (
    ("fixture", "./" + PREFIX + "fixture", "TestFixedHookSchemasAreClosedAndCommandsStayJSON"),
    ("payload", "./" + PREFIX + "payload", "TestFixedHookExchangeUsesExistingNativeClientWithoutOverride"),
    ("oracle", "./internal/gateway", "TestFixedContainedHookSharedEvaluatorOracleWithoutNative"),
    ("custody", "./internal/gateway", "TestFixedContainedHookCleanupRetainsUncertainOwnerWithoutNative"),
)
# Filled from the stationary reviewed source; no caller-provided hash exists.
PINS = {
    "LICENSE": {"sha256": "d7ffeba6d77375d880ff69d61477e9c41c7101d55d2b0eb986f8380643ccc299", "bytes": 11393},
    "NOTICE": {"sha256": "a0c1a94eafbe9cfa7a98af7ace69c74f12d5a5057628a1bebc08f5af1dcd8aff", "bytes": 7863},
    "THIRD_PARTY_LICENSES.txt": {
        "sha256": "76f7cb67f51071eabf94dbb618ff61fbf50271c09cbc851306e4f546f27e53fa",
        "bytes": 151739,
    },
    "go.mod": {"sha256": "37c86768672180ef16cef850a1552e6b63728d480df7762c1f0e46147aadcef5", "bytes": 8625},
    "go.sum": {"sha256": "15096dcef418f763d24350258b9c3e57adcbbedcf97fc7297ea0c32a2e568916", "bytes": 43401},
    "internal/axis/bridgeprocess/start.go": {
        "sha256": "d54486f60e4ac1454fab2fce876c34c1135cdd91d1ea340a00bc727c3c71ea2f",
        "bytes": 4025,
    },
    "internal/axis/bridgeprocess/start_linux.go": {
        "sha256": "f26f5cc066d93ca7735353eaf678893c2e7101f4e3d0833bc6d2b36ce3be0c3d",
        "bytes": 10504,
    },
    "internal/gateway/agent_hook_e2e_test.go": {
        "sha256": "6f5dd5a94be42080f0e480af8d64a65669a0ec26aa0802850651578ff80b40fa",
        "bytes": 33726,
    },
    "internal/gateway/api_sandbox_ingress_test.go": {
        "sha256": "22143d0966e8023c3a029129e4a8b7bf01f15558121cf45e3f49040df669508d",
        "bytes": 71137,
    },
    "internal/gateway/connector/hook_contract.go": {
        "sha256": "ae485692d69891ebb2b48796021c1371bc7153128693f01ad81b7ae8424cf304",
        "bytes": 67868,
    },
    "internal/gateway/connector/hookexec/native_sandbox.go": {
        "sha256": "6946d26455c7bbd28d6655710c095570b73629534521be9f128a44000065ddb3",
        "bytes": 7638,
    },
    "internal/gateway/connector/hookexec/spec.go": {
        "sha256": "6fad71acf7961fed63282e375423f9ba2917a6d6ef8dca808d2b4b170d2677b6",
        "bytes": 13249,
    },
    "internal/gateway/native_sandbox_hook_assets.go": {
        "sha256": "f4c1b788eb801f6760206a4b8f535762f24d0da0fae51fb31e2f2ec056495eaf",
        "bytes": 9924,
    },
    "internal/gateway/native_sandbox_hook_assets_linux.go": {
        "sha256": "4c85a45667b44eb8019e2c7f18f44443f2c2bdf4e1f93b607106d580c92a4637",
        "bytes": 18138,
    },
    "internal/gateway/native_sandbox_hook_contained_canary_linux_test.go": {
        "sha256": "949fa0194b3e9985db9872b71c66bce8a5e31b5917a394c162800a36ad957581",
        "bytes": 48820,
    },
    "internal/gateway/native_sandbox_hook_contained_pin_linux_test.go": {
        "sha256": "33aedf3fc8b6afefc40f5252be3ba133f23080766a718f6990cf90569100fac2",
        "bytes": 523,
    },
    "internal/gateway/native_sandbox_hook_ingress.go": {
        "sha256": "8a7c7f946f2850b8ed80a1a86e9a6bbefc451d5c5d2bd7775a04caec864caf20",
        "bytes": 8928,
    },
    "test/e2e/axis/native-hook-canary/fixture/cases.go": {
        "sha256": "a29ebaf081a2f9c70cb8977207e5cb4c0db2ec377afed69099cf8b33995e316c",
        "bytes": 6305,
    },
    "test/e2e/axis/native-hook-canary/fixture/cases_test.go": {
        "sha256": "ee967fd63cb014b3958a60df9ff6264a9c151a67ec1e54a02acced8f84b1702f",
        "bytes": 3466,
    },
    "test/e2e/axis/native-hook-canary/payload/main_linux.go": {
        "sha256": "b7356ca99c7210b65d608bde8a30ae339786d77c3d7d76998561b8727d068214",
        "bytes": 3681,
    },
    "test/e2e/axis/native-hook-canary/payload/main_linux_test.go": {
        "sha256": "0508b28e8b17898f2285492481525f04b3174681b0fe005951ab81d512f2635d",
        "bytes": 1386,
    },
    "test/e2e/axis/native-peer/driver/images_linux.go": {
        "sha256": "4d114944ed73a5f986061de18be86f51a78c78e72cd4737f28ba62bf4bd85a5a",
        "bytes": 10724,
    },
}


def require(condition, reason):
    if not condition:
        raise RefusedError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, bound):
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= bound,
        "source/output type or bound differs",
    )
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "source/output changed during read")
    return raw


def checked_sources(repo, overlay=None):
    """Dry check can select TASK copies, but never accepts replacement pins."""
    result = {}
    require(len(PINS) >= 19, "source inventory is closed")
    for name, expected in PINS.items():
        path = repo / name
        if overlay is not None and (overlay / name).exists():
            path = overlay / name
        raw = regular(path, 8 << 20)
        require((sha(raw), len(raw)) == (expected["sha256"], expected["bytes"]), "fixed source differs")
        result[name] = {"sha256": sha(raw), "bytes": len(raw)}
    return result


def generated_pin(template, digest):
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "payload digest is not canonical")
    needle = b'const containedPayloadSHA = ""'
    require(
        template.count(needle) == 1 and template.count(b"const containedPayloadSHA") == 1, "closed pin template differs"
    )
    return template.replace(needle, b'const containedPayloadSHA = "sha256:' + digest.encode("ascii") + b'"')


def check_test_log(raw, selector, children=()):
    require(len(raw) <= 32 << 20, "host test log exceeds bound")
    expected = {selector, *(selector + "/" + child for child in children)}
    passes = []
    package_passes = 0
    for line in raw.splitlines():
        require(0 < len(line) <= 1 << 20, "host test line exceeds bound")
        item = json.loads(line)
        require(
            isinstance(item, dict) and item.get("Action") not in {"fail", "skip"}, "safe host test failed or skipped"
        )
        if "Test" in item:
            require(item["Test"] in expected, "unexpected test selected")
            if item.get("Action") == "pass":
                passes.append(item["Test"])
        elif item.get("Action") == "pass":
            package_passes += 1
    require(
        set(passes) == expected and len(passes) == len(expected) and package_passes == 1,
        "safe host test pass inventory differs",
    )
    return sorted(passes)


def json_objects(raw):
    decoder = json.JSONDecoder()
    text = raw.decode("utf-8")
    offset = 0
    result = []
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset < len(text):
            item, offset = decoder.raw_decode(text, offset)
            result.append(item)
    return result


def run(argv, cwd, env, log, seconds=900, bound=32 << 20):
    # Child output is file-backed and polled; it is never accumulated without a
    # bound. These argv are all source literals below, never an image path.
    with log.open("xb") as output:
        process = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT
        )
        start = time.monotonic()
        while process.poll() is None:
            if log.stat().st_size > bound or time.monotonic() - start > seconds:
                process.kill()
                process.wait(timeout=10)
                raise RefusedError("host compiler/reader deadline or output bound")
            time.sleep(0.1)
        require(process.returncode == 0 and log.stat().st_size <= bound, "host source test/compiler/reader failed")
    return regular(log, bound)


def git(repo, *args):
    # Even reader output is file-backed before its bound is checked.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        subprocess.run(
            ["git", *args], cwd=repo, stdin=subprocess.DEVNULL, stdout=output, stderr=error, timeout=60, check=True
        )
        require(output.tell() <= 64 << 20 and error.tell() <= 4096, "Git metadata exceeds bound")
        output.seek(0)
        return output.read((64 << 20) + 1)


def source_closure(repo, packages, generated):
    """Bind every selected local compiler/embed input to the exact Git head."""
    entries = {}
    fields = (
        "GoFiles",
        "CgoFiles",
        "CFiles",
        "CXXFiles",
        "MFiles",
        "HFiles",
        "FFiles",
        "SFiles",
        "SwigFiles",
        "SwigCXXFiles",
        "SysoFiles",
        "EmbedFiles",
        "TestGoFiles",
        "XTestGoFiles",
        "TestEmbedFiles",
        "XTestEmbedFiles",
    )
    base = repo.resolve()
    for package in packages:
        # Go synthesizes this one test main from the selected trusted tests.
        # Its cache path is compiler output, not a Git source input. Keep the
        # full package metadata, but do not mistake it for a local source leaf.
        if (
            package.get("ImportPath") == "github.com/defenseclaw/defenseclaw/internal/gateway.test"
            and package.get("Name") == "main"
        ):
            continue
        directory = Path(package.get("Dir", "")).resolve()
        if not directory.is_relative_to(base):
            continue
        for field in fields:
            for leaf in package.get(field, ()):
                path = directory / leaf
                require(path.resolve().is_relative_to(base), "local input escapes checkout")
                name = path.relative_to(base).as_posix()
                raw = regular(path, 32 << 20)
                expected = generated if name == PIN else git(repo, "cat-file", "blob", "HEAD:" + name)
                require(raw == expected, "local compiler input differs from exact Git/generated source")
                entries[name] = {"sha256": sha(raw), "bytes": len(raw)}
    require(PIN in entries and len(entries) >= 100, "local compiler closure incomplete")
    return dict(sorted(entries.items()))


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def build():
    require(
        sys.platform == "linux"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_REF") == REF
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
        "build-only CI admission refused",
    )
    repo = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    source_head = git(repo, "rev-parse", "HEAD").decode().strip()
    require(
        re.fullmatch(r"[0-9a-f]{40}", source_head) is not None
        and source_head == os.environ.get("GITHUB_SHA")
        and not git(repo, "status", "--porcelain"),
        "exact clean checkout required",
    )
    frozen = checked_sources(repo)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve() / "fixed-contained-hook-build"
    temp.mkdir(mode=0o700)  # never reuse an earlier output/staging tree
    artifact = repo / "contained-hook-build-artifact"
    artifact.mkdir(mode=0o700)
    (artifact / "sources").mkdir()
    for name in PINS:
        target = artifact / "sources" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(regular(repo / name, 8 << 20))
    for name in (
        PREFIX + "build_only.py",
        PREFIX + "test_build_only.py",
        PREFIX + "README.md",
        ".github/workflows/axis-contained-hook-canary-build.yml",
    ):
        target = artifact / "sources" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(regular(repo / name, 8 << 20))
    # GOENV off and closed Go settings prevent per-user flag/workspace/toolchain
    # overrides. Cache/dependency locations are disposable and job-private.
    env = dict(os.environ)
    env.update(
        {
            "GOENV": "off",
            "GOWORK": "off",
            "GOTOOLCHAIN": "local",
            "GOFLAGS": "",
            "GOEXPERIMENT": "",
            "GODEBUG": "",
            "GOOS": "linux",
            "GOARCH": "amd64",
            "GOAMD64": "v1",
            "CGO_ENABLED": "1",
            "GOPROXY": "https://proxy.golang.org",
            "GOSUMDB": "sum.golang.org",
            "GOPRIVATE": "",
            "GONOPROXY": "",
            "GONOSUMDB": "",
            "GOCACHE": str(temp / "cache"),
            "GOMODCACHE": str(temp / "modules"),
            "GOTMPDIR": str(temp / "tmp"),
        }
    )
    (temp / "tmp").mkdir()
    go = shutil.which("go")
    require(go is not None, "pinned host Go reader unavailable")
    version = run([go, "version"], repo, env, artifact / "toolchain.txt", seconds=30, bound=4096)
    require(version.strip() == b"go version go1.26.5 linux/amd64", "Go toolchain differs")
    run([go, "mod", "download"], repo, env, artifact / "module-download.txt")
    run([go, "mod", "verify"], repo, env, artifact / "module-verify-before.txt")
    require(checked_sources(repo) == frozen, "dependency command changed frozen source")
    passes = {}
    for label, package, selector in SAFE_TESTS[:2]:
        raw = run(
            [
                go,
                "test",
                "-race",
                "-p",
                "1",
                "-mod=readonly",
                "-count=1",
                "-timeout=2m",
                "-json",
                "-run",
                "^" + selector + "$",
                package,
            ],
            repo,
            env,
            artifact / (label + "-tests.jsonl"),
        )
        passes[label] = check_test_log(raw, selector)
    payload_env = dict(env, CGO_ENABLED="0")
    payload_path = artifact / "fixed-hook-payload"
    run(
        [
            go,
            "build",
            "-p",
            "1",
            "-mod=readonly",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-buildid= -w -s",
            "-o",
            str(payload_path),
            "./" + PREFIX + "payload",
        ],
        repo,
        payload_env,
        artifact / "payload-build.txt",
    )
    payload = regular(payload_path, 32 << 20)
    generated = generated_pin(regular(repo / PIN, 8192), sha(payload))
    (repo / PIN).write_bytes(generated)
    (artifact / "generated-payload-pin.go").write_bytes(generated)
    label, package, selector = SAFE_TESTS[2]
    raw = run(
        [
            go,
            "test",
            "-race",
            "-p",
            "1",
            "-mod=readonly",
            "-count=1",
            "-timeout=3m",
            "-tags",
            TAG,
            "-json",
            "-run",
            "^" + selector + "$",
            package,
        ],
        repo,
        env,
        artifact / "oracle-tests.jsonl",
        seconds=1200,
    )
    passes[label] = check_test_log(raw, selector, CONNECTORS)
    label, package, selector = SAFE_TESTS[3]
    raw = run(
        [
            go,
            "test",
            "-race",
            "-p",
            "1",
            "-mod=readonly",
            "-count=1",
            "-timeout=1m",
            "-tags",
            TAG,
            "-json",
            "-run",
            "^" + selector + "$",
            package,
        ],
        repo,
        env,
        artifact / "custody-tests.jsonl",
        seconds=1200,
    )
    passes[label] = check_test_log(raw, selector)
    listed = run(
        [go, "list", "-mod=readonly", "-deps", "-test", "-tags", TAG, "-json", package],
        repo,
        payload_env,
        artifact / "compiler-packages.json",
        bound=64 << 20,
    )
    closure = source_closure(repo, json_objects(listed), generated)
    write_json(artifact / "local-compiler-inputs.json", closure)
    driver = artifact / "fixed-contained-hook-driver.test"
    # -c compiles only: no test/main in this file or the contained payload runs.
    run(
        [
            go,
            "test",
            "-c",
            "-p",
            "1",
            "-mod=readonly",
            "-tags",
            TAG,
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-buildid= -w -s",
            "-o",
            str(driver),
            package,
        ],
        repo,
        payload_env,
        artifact / "driver-compile-only.txt",
        seconds=1200,
    )
    driver_raw = regular(driver, 256 << 20)
    for label, path in (("payload", payload_path), ("driver", driver)):
        run(
            [go, "version", "-m", str(path)],
            repo,
            env,
            artifact / (label + "-buildinfo.txt"),
            seconds=30,
            bound=1 << 20,
        )
    run([go, "list", "-mod=readonly", "-m", "-json", "all"], repo, env, artifact / "modules.json", bound=16 << 20)
    run([go, "mod", "verify"], repo, env, artifact / "module-verify-after.txt")
    require(
        git(repo, "diff", "--name-only", "HEAD").decode().splitlines() == [PIN], "unexpected tracked source mutation"
    )
    require(regular(repo / PIN, 8192) == generated, "generated admission changed")
    # Recheck every selected local input after the compiler; retain both the
    # Git-bound original template and the only permitted generated variant.
    require(source_closure(repo, json_objects(listed), generated) == closure, "compiler source changed")
    write_json(
        artifact / "BUILD-RESULT.json",
        {
            "source": source_head,
            "source_tree": git(repo, "rev-parse", "HEAD^{tree}").decode().strip(),
            "repository": REPOSITORY,
            "ref": REF,
            "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": 1,
            "scope": "build-only synthetic contained-hook inputs; no native test/image execution",
            "safe_host_passes": passes,
            "frozen_sources": frozen,
            "generated_payload_sha256": sha(payload),
            "payload_bytes": len(payload),
            "generated_pin_sha256": sha(generated),
            "driver_sha256": sha(driver_raw),
            "driver_bytes": len(driver_raw),
            "native_execution": False,
            "production_qualification": False,
            "peer_acquisition": False,
        },
    )
    records = {}
    for path in sorted(artifact.rglob("*")):
        if path.is_file():
            raw = regular(path, 256 << 20)
            records[path.relative_to(artifact).as_posix()] = {"sha256": sha(raw), "bytes": len(raw)}
    require(sum(item["bytes"] for item in records.values()) <= 384 << 20, "artifact aggregate exceeds bound")
    write_json(artifact / "PROVENANCE.json", {"source": source_head, "files": records})


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--dry-check":
        result = checked_sources(Path(sys.argv[2]), Path(sys.argv[3]))
        print(json.dumps({"source_only": True, "checked": result}, sort_keys=True))
        return
    require(len(sys.argv) == 1, "no runtime build inputs or selector overrides accepted")
    build()


if __name__ == "__main__":
    try:
        main()
    except (RefusedError, OSError, ValueError, subprocess.SubprocessError):
        # Keep file-backed logs for root review; do not expose exception paths.
        print("fixed contained-hook build refused", file=sys.stderr)
        raise SystemExit(1) from None
