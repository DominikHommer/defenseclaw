#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Compile the fixed outer custodian for inert review; never execute it."""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

REPOSITORY = "cisco-ai-defense/defenseclaw"
REF = "refs/heads/codex/axis-sandbox-feasibility"
PACKAGE = "./test/e2e/axis/native-hook-canary/live"
SOURCE = "test/e2e/axis/native-hook-canary/live/"
FIXTURE_SOURCE = "test/e2e/axis/native-hook-canary/fixture/cases.go"
FIXTURE_SHA = "a29ebaf081a2f9c70cb8977207e5cb4c0db2ec377afed69099cf8b33995e316c"
GO_VERSION = b"go version go1.26.5 linux/amd64"
TEST_PACKAGE = "github.com/defenseclaw/defenseclaw/test/e2e/axis/native-hook-canary/live"
PURE_TESTS = (
    "TestStrictCaseJSONRefusesDuplicateKeys",
    "TestClaudeCaseRefusesFalsePass",
    "TestOutputGateRejectsLastWinsRecord",
)
PURE_TEST_RUN = "^(" + "|".join(PURE_TESTS) + ")$"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_bytes(path, bound):
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= bound,
        "fixed source/output type refused",
    )
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "fixed source/output read differs")
    return raw


def run(argv, cwd, env, log, seconds=900, bound=32 << 20):
    with log.open("xb") as output:
        process = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT
        )
        start = time.monotonic()
        while process.poll() is None:
            if log.stat().st_size > bound or time.monotonic() - start > seconds:
                process.kill()
                process.wait(timeout=10)
                raise ValueError("fixed compiler/reader bound exceeded")
            time.sleep(0.1)
        require(process.returncode == 0 and log.stat().st_size <= bound, "fixed compiler/reader failed")
    return file_bytes(log, bound)


def git(repo, *args):
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=60,
        check=True,
    )
    require(len(result.stdout) <= 64 << 20 and len(result.stderr) <= 4096, "fixed Git reader bound")
    return result.stdout


def json_objects(raw):
    decoder = json.JSONDecoder()
    text = raw.decode("utf-8")
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            return
        item, offset = decoder.raw_decode(text, offset)
        yield item


def closure(repo, packages):
    base = repo.resolve()
    fields = (
        "GoFiles",
        "CgoFiles",
        "CFiles",
        "CXXFiles",
        "MFiles",
        "HFiles",
        "FFiles",
        "SFiles",
        "SysoFiles",
        "EmbedFiles",
    )
    entries = {}
    for package in packages:
        directory = Path(package.get("Dir", "")).resolve()
        if not directory.is_relative_to(base):
            continue
        for field in fields:
            for leaf in package.get(field, ()):
                path = directory / leaf
                require(path.resolve().is_relative_to(base), "local compiler path escapes checkout")
                name = path.relative_to(base).as_posix()
                raw = file_bytes(path, 32 << 20)
                require(
                    raw == git(repo, "cat-file", "blob", "HEAD:" + name),
                    "local compiler source differs from exact Git blob",
                )
                entries[name] = {"sha256": sha(raw), "bytes": len(raw)}
    require(
        len(entries) >= 6
        and all(
            SOURCE + name in entries for name in ("main_linux.go", "images_linux.go", "custody_linux.go", "cleanup.go")
        ),
        "fixed local compiler closure incomplete",
    )
    require(
        entries.get(FIXTURE_SOURCE, {}).get("sha256") == FIXTURE_SHA,
        "reviewed shared strict fixture is absent from compiled closure",
    )
    return dict(sorted(entries.items()))


def verify_pure_tests(raw):
    runs = {name: 0 for name in PURE_TESTS}
    passes = {name: 0 for name in PURE_TESTS}
    package_pass = 0
    for event in json_objects(raw):
        require(isinstance(event, dict) and event.get("Package") == TEST_PACKAGE, "fixed pure-test package differs")
        action = event.get("Action")
        require(action not in ("fail", "skip"), "fixed pure test failed or skipped")
        name = event.get("Test")
        if name is None:
            if action == "pass":
                package_pass += 1
            continue
        require(isinstance(name, str), "fixed pure-test name malformed")
        root = name.split("/", 1)[0]
        require(root in runs and (name == root or root == "TestClaudeCaseRefusesFalsePass"), "unlisted pure test ran")
        if name == root and action == "run":
            runs[root] += 1
        if name == root and action == "pass":
            passes[root] += 1
    require(
        package_pass == 1 and all(runs[name] == 1 and passes[name] == 1 for name in PURE_TESTS),
        "fixed pure-test pass inventory differs",
    )


def build():
    require(
        sys.platform == "linux"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_REF") == REF
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
        "fixed build-only route refused",
    )
    require(len(sys.argv) == 1, "no runtime build inputs")
    repo = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    require(
        re.fullmatch(r"[0-9a-f]{40}", head)
        and head == os.environ.get("GITHUB_SHA")
        and not git(repo, "status", "--porcelain"),
        "exact clean checkout required",
    )
    source = file_bytes(repo / SOURCE / "main_linux.go", 64 << 10).decode("utf-8")
    require(
        re.search(r'^const payloadSHA = "[0-9a-f]{64}"$', source, re.MULTILINE)
        and re.search(r'^const testDriverSHA = "[0-9a-f]{64}"$', source, re.MULTILINE),
        "fixed wrapper admission still closed",
    )
    require(
        re.search(r"^const payloadSize int64 = [1-9][0-9]*$", source, re.MULTILINE)
        and re.search(r"^const testDriverSize int64 = [1-9][0-9]*$", source, re.MULTILINE),
        "fixed image sizes still closed",
    )
    temp = Path(os.environ["RUNNER_TEMP"]).resolve() / "fixed-contained-hook-outer-build"
    temp.mkdir(mode=0o700)
    (temp / "tmp").mkdir(mode=0o700)
    artifact = repo / "contained-hook-outer-build-artifact"
    artifact.mkdir(mode=0o700)
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
            "CGO_ENABLED": "0",
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
    go = shutil.which("go")
    require(go is not None, "pinned Go compiler unavailable")
    require(
        run([go, "version"], repo, env, artifact / "toolchain.txt", seconds=30, bound=4096).strip() == GO_VERSION,
        "Go toolchain differs",
    )
    run([go, "mod", "download"], repo, env, artifact / "module-download.txt")
    run([go, "mod", "verify"], repo, env, artifact / "module-verify-before.txt")
    listed = run(
        [go, "list", "-mod=readonly", "-deps", "-json", PACKAGE],
        repo,
        env,
        artifact / "compiler-packages.json",
        bound=64 << 20,
    )
    inputs = closure(repo, json_objects(listed))
    (artifact / "local-compiler-inputs.json").write_text(
        json.dumps(inputs, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    test_source = SOURCE + "main_linux_test.go"
    require(
        file_bytes(repo / test_source, 1 << 20) == git(repo, "cat-file", "blob", "HEAD:" + test_source),
        "fixed pure-test source differs",
    )
    pure_log = run(
        [go, "test", "-p", "1", "-mod=readonly", "-count=1", "-json", "-run", PURE_TEST_RUN, PACKAGE],
        repo,
        env,
        artifact / "pure-parser-tests.jsonl",
        seconds=300,
        bound=8 << 20,
    )
    verify_pure_tests(pure_log)
    image = artifact / "fixed-contained-hook-outer"
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
            str(image),
            PACKAGE,
        ],
        repo,
        env,
        artifact / "outer-compile-only.txt",
        seconds=1200,
    )
    raw = file_bytes(image, 64 << 20)
    run([go, "version", "-m", str(image)], repo, env, artifact / "outer-buildinfo.txt", seconds=30, bound=1 << 20)
    run([go, "list", "-mod=readonly", "-m", "-json", "all"], repo, env, artifact / "modules.json", bound=16 << 20)
    run([go, "mod", "verify"], repo, env, artifact / "module-verify-after.txt")
    require(not git(repo, "status", "--porcelain", "--untracked-files=no"), "compiler modified tracked source")
    require(closure(repo, json_objects(listed)) == inputs, "compiler source changed")
    for name in (
        "main_linux.go",
        "main_linux_test.go",
        "images_linux.go",
        "custody_linux.go",
        "cleanup.go",
        "prepare.py",
        "build_wrapper_only.py",
    ):
        target = artifact / "sources" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        raw_source = file_bytes(repo / SOURCE / name, 1 << 20)
        require(raw_source == git(repo, "cat-file", "blob", "HEAD:" + SOURCE + name), "fixed recipe source changed")
        target.write_bytes(raw_source)
    result = {
        "source": head,
        "scope": "fixed_contained_hook_outer_build_only",
        "wrapper_sha256": sha(raw),
        "wrapper_bytes": len(raw),
        "native_execution": False,
        "production_qualification": False,
    }
    (artifact / "BUILD-RESULT.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    files = {
        p.relative_to(artifact).as_posix(): {"sha256": sha(file_bytes(p, 128 << 20)), "bytes": p.stat().st_size}
        for p in sorted(artifact.rglob("*"))
        if p.is_file()
    }
    require(sum(value["bytes"] for value in files.values()) <= 256 << 20, "outer artifact aggregate exceeded")
    (artifact / "PROVENANCE.json").write_text(
        json.dumps({"source": head, "files": files}, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    try:
        build()
    except (ValueError, OSError, subprocess.SubprocessError):
        print("fixed contained-hook outer build refused", file=sys.stderr)
        raise SystemExit(1) from None
