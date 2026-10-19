# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Compile a fixed Windows harness; never execute an image or native workload."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
from pathlib import Path

WORKFLOW = ".github/workflows/axis-native-harness-build.yml"
HELPER = "test/e2e/axis/windows/native-peer/prepare_harness_build.py"
HELPER_TEST = "test/e2e/axis/windows/native-peer/test_prepare_harness_build.py"
HARNESS = "test/e2e/axis/windows/native-peer"
PAYLOAD = HARNESS + "/payload"
PROTO = "internal/axis/bridgeproto"
GENERATED = ".hosted/windows-native-peer-harness-pinned"
MODULE = {
    "Path": "golang.org/x/sys",
    "Version": "v0.47.0",
    "Sum": "h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=",
    "GoModSum": "h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw=",
}
# ROOT fills this source literal only after the peer and existing payload have
# independent artifact reviews. No command line, environment or file supplies it.
# Shape: receipt_utf8 (exact reviewed JSON bytes as a string), peer_sha256,
# peer_size, payload_sha256, payload_size. None refuses before downloads/builds.
REVIEWED = {
    "receipt_utf8": (
        "{\n"
        "  \"harness_source\": {\n"
        "    \"base_commit\": \"1449006dae8a007deb9738774bc6bfd24f0af467\",\n"
        "    \"canonical_registry_closed\": true,\n"
        "    \"main_windows_go_sha256\": \"15546f7b32b3889c797c41d9913d11fb98e14a49ba3ed7011c50ac0db4950cef\",\n"
        "    \"run_windows_go_sha256\": \"d4d9c88ae4b7dfe72da9fd1eb64e0c37523a92df55e27bcdde4ef87200707966\"\n"
        "  },\n"
        "  \"hook_activation\": false,\n"
        "  \"payload\": {\n"
        "    \"build_info_sha256\": \"0221f59a8e69c8860e07c2da25e27945e3d1a4edca812c2e44ceda4800a55d40\",\n"
        "    \"build_result_sha256\": \"1b3d4be3136080df00b83f23192c6e662cba30ea1fad4a1ed523a7875cb1e77f\",\n"
        "    \"go_version\": \"go1.26.5\",\n"
        "    \"image_sha256\": \"37de1dd01607e830fc05a88b6105e386da0d3f8ebb83ca48dfbafad43999f40d\",\n"
        "    \"size\": 2434048,\n"
        "    \"source_member\": \"test/e2e/axis/windows/native-peer/payload/main_windows.go\",\n"
        "    \"source_sha256\": \"cce013d7dffba8769fee8eae29985044f9d37eae77803d1e8c59336a3104c25d\"\n"
        "  },\n"
        "  \"peer\": {\n"
        "    \"artifact_archive_sha256\": \"7ab3adf1142a258484e3f53b8b37b44f337351b1c784a75cee29f1bddde6f28f\",\n"
        "    \"artifact_id\": 12201168403,\n"
        "    \"image_sha256\": \"bf4074258228425353248222dc1b85b78c85531b38b4fcc450bc66fd3b7046f9\",\n"
        "    \"repository\": \"cisco-ai-defense/defenseclaw\",\n"
        "    \"run_id\": 39282658307,\n"
        "    \"size\": 1472000,\n"
        "    \"source_commit\": \"06f0c9307821ab860e5002c255e22d3cfce44d78\",\n"
        "    \"workflow\": \".github/workflows/axis-native-peer-windows-build.yml\"\n"
        "  },\n"
        "  \"production_qualification\": false,\n"
        "  \"schema\": \"windows-fixed-native-token-probe-images-v1\",\n"
        "  \"scope\": \"fixed contributor canary images for hosted harness build only\"\n"
        "}\n"
    ),
    "peer_sha256": "bf4074258228425353248222dc1b85b78c85531b38b4fcc450bc66fd3b7046f9",
    "peer_size": 1472000,
    "payload_sha256": "37de1dd01607e830fc05a88b6105e386da0d3f8ebb83ca48dfbafad43999f40d",
    "payload_size": 2434048,
}
DIRECTORIES = {
    "internal/axis/bridgeproto": [
        "README.md",
        "codec.go",
        "fuzz_test.go",
        "hook_test.go",
        "message.go",
        "native_stage_test.go",
        "native_token_observation_test.go",
        "protocol_test.go",
        "state.go",
    ],
    "internal/axis/bridgeowner": [
        "README.md",
        "owner.go",
        "owner_test.go",
        "pipe.go",
        "pipe_child_overlapped_windows.go",
        "pipe_child_overlapped_windows_test.go",
        "pipe_other.go",
        "pipe_test.go",
        "pipe_windows.go",
        "pipe_windows_test.go",
    ],
    "internal/axis/bridgeprocess": [
        "README.md",
        "asset_windows_test.go",
        "bootstrap_windows.go",
        "cleanup_stage_windows_test.go",
        "image_linux.go",
        "image_windows.go",
        "image_windows_test.go",
        "start.go",
        "start_linux.go",
        "start_linux_test.go",
        "start_other.go",
        "start_other_test.go",
        "start_stage_windows_test.go",
        "start_test.go",
        "start_windows.go",
        "start_windows_nochild_test.go",
        "start_windows_signal_order_test.go",
        "start_windows_test.go",
    ],
    "internal/safefile": [
        "protect_in_use_other.go",
        "protect_in_use_windows.go",
        "protect_other.go",
        "protect_windows.go",
        "protect_windows_test.go",
        "read_fifo_other_test.go",
        "read_other.go",
        "read_security_regression_test.go",
        "read_stability.go",
        "read_stability_darwin.go",
        "read_stability_linux.go",
        "read_stability_other.go",
        "read_stability_windows.go",
        "read_windows.go",
        "read_windows_test.go",
        "reclaim_unix.go",
        "reclaim_windows.go",
        "rename_other.go",
        "rename_windows.go",
        "rename_windows_test.go",
        "safefile.go",
        "safefile_test.go",
    ],
    "internal/winpath": [
        "enterprise_deployment_record_windows_test.go",
        "enterprise_layout.go",
        "enterprise_layout_test.go",
        "enterprise_layout_windows.go",
        "enterprise_profile_contract_test.go",
        "known_folder_windows.go",
        "machine_roots_windows.go",
        "managed_ipc_other.go",
        "managed_ipc_windows.go",
        "mounted_volume_windows.go",
        "mounted_volume_windows_test.go",
        "path_windows.go",
        "path_windows_test.go",
        "user_sid.go",
        "user_sid_test.go",
    ],
    "test/e2e/axis/windows/native-peer": [
        "README.md",
        "main_windows.go",
        "main_windows_test.go",
        "manual-results.md",
        "native_signal_diagnostic_windows_test.go",
        "payload/main_windows.go",
        "payload/main_windows_test.go",
        "prepare_harness_build.py",
        "run_windows.go",
        "test_prepare_harness_build.py",
    ],
}
ROOT_FILES = ("go.mod", "go.sum", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt", WORKFLOW)
LOCAL_PACKAGES = frozenset(
    (
        PROTO,
        "internal/axis/bridgeowner",
        "internal/axis/bridgeprocess",
        "internal/safefile",
        "internal/winpath",
        HARNESS,
    )
)
TESTS = {
    HARNESS: (
        "TestFixedCanaryProtocolRequiresExactStreamsExitBindingAndDestroy",
        "TestFixedCanaryRegistryIsClosedAndWindowsPlanIsExplicit",
        "TestFixedFailureDiagnosticsPreserveJoinedClassesAndNeverFormatRawErrors",
        "TestFixedFailureDiagnosticRefusesUnrecognizedNativeStartStages",
        "TestFixedProtocolFailureDiagnosticsRequireValidatedCorrelationAndRedactCauses",
        "TestFixedPreparationDiagnosticRequiresCorrelatedValidatedFailure",
        "TestFixedTokenFactsAreReportedOnlyAfterCorrelatedStarted",
        "TestFixedNativeSignalDiagnosticRetainsBothClosedRolesOnlyAtSignalStage",
    ),
    PAYLOAD: ("TestFixedPrivateInputFrameRefusesTruncationExtraTargetAndMissingPort",),
    PROTO: (
        "TestNativePreparationStageIsClosedDiagnosticAndAbsencePreservesBytes",
        "TestNativeTokenObservationCannotBypassStartedCorrelation",
        "TestNativeTokenObservationIsStartedOnlyAndAbsentBytesStayExact",
        "TestNativeTokenObservationRejectsMissingNullAmbiguousOrPrivateFields",
        "TestProtocolAdmittedFailureStillRequiresOwnedCleanup",
        "TestProtocolCompletionCrossingInFlightControls",
        "TestProtocolLengthAndPartialIOFailuresRemainClosed",
        "TestProtocolLiteralPreparationRoundTripAndNoReadAhead",
        "TestProtocolOutputLimitIncludesAllAcceptedFrames",
        "TestProtocolPreparationRefusesChangedPlanAndWindowsEnvAliases",
        "TestProtocolRejectsAmbiguousJSONAndPoisonsStream",
        "TestProtocolReplaysForeignBindingsAndEarlyLaunchPermanentlyRefuse",
        "TestProtocolRunningCancellationCompletionAndDestroy",
        "TestProtocolUnicodeEscapeDomain",
        "TestTypedHookRequiresExactSessionAndOneFixedReadSlot",
    ),
}
NATIVE_FIELDS = ("CFiles", "CXXFiles", "MFiles", "FFiles", "SwigFiles", "SwigCXXFiles", "CgoFiles", "SysoFiles")
COMPILED_FIELDS = ("GoFiles", "SFiles", "HFiles")
NO_EXECUTION = {
    "harness_peer_payload_or_psec_execution": False,
    "native_child_or_job_test_execution": False,
    "production_qualification": False,
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ordinary(path, bound=2 << 20):
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and not path.is_symlink() and 0 <= info.st_size <= bound, "ordinary input refused"
    )
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "input changed")
    return raw


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        require(stream.write(raw) == len(raw), "evidence write refused")


def document(path, value):
    write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def reviewed_registry(value):
    require(
        type(value) is dict
        and set(value) == {"receipt_utf8", "peer_sha256", "peer_size", "payload_sha256", "payload_size"},
        "reviewed source literal is closed",
    )
    for role in ("peer", "payload"):
        require(
            type(value[role + "_size"]) is int and 64 <= value[role + "_size"] <= 64 << 20,
            "reviewed image size refused",
        )
        require(
            type(value[role + "_sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value[role + "_sha256"]),
            "reviewed image hash refused",
        )
    require(type(value["receipt_utf8"]) is str, "reviewed receipt type refused")
    raw = value["receipt_utf8"].encode("utf-8", errors="strict")
    require(2 <= len(raw) <= 64 << 10, "reviewed receipt bound refused")
    receipt = json.loads(raw, object_pairs_hook=unique_object)
    require(
        type(receipt) is dict and receipt.get("production_qualification") is False, "reviewed receipt scope refused"
    )
    for role in ("peer", "payload"):
        image = receipt.get(role)
        require(
            type(image) is dict
            and image.get("image_sha256") == value[role + "_sha256"]
            and type(image.get("size")) is int
            and image["size"] == value[role + "_size"],
            "reviewed receipt image differs",
        )
    return raw


def pin_main(raw, value):
    receipt = reviewed_registry(value)
    closed = b"var reviewed = artifactRegistry{}"
    require(raw.count(closed) == 1, "canonical registry must remain closed")
    replacement = (
        f'var reviewed = artifactRegistry{{Enabled: true, Receipt: "{sha(receipt)}", '
        f'Peer: "{value["peer_sha256"]}", Payload: "{value["payload_sha256"]}", '
        f"PeerSize: {value['peer_size']}, PayloadSize: {value['payload_size']}}}"
    ).encode("ascii")
    generated = raw.replace(closed, replacement, 1)
    require(generated.replace(replacement, closed, 1) == raw, "generated source delta refused")
    return generated, receipt, {"replacement_count": 1, "closed": closed.decode(), "enabled": replacement.decode()}


def passed_tests(raw, expected):
    require(0 < len(raw) <= 4 << 20, "test log bound refused")
    rows = [json.loads(line, object_pairs_hook=unique_object) for line in raw.splitlines()]
    require(
        all(type(row) is dict and row.get("Action") not in ("skip", "fail") for row in rows), "test failure or skip"
    )
    roots = [row["Test"] for row in rows if row.get("Action") == "pass" and "Test" in row and "/" not in row["Test"]]
    require(sorted(roots) == sorted(expected) and len(roots) == len(set(roots)), "exact pure roots differ")
    all_passes = [row["Test"] for row in rows if row.get("Action") == "pass" and "Test" in row]
    require(
        len(all_passes) == len(set(all_passes)) and all(name.split("/", 1)[0] in expected for name in all_passes),
        "test row inventory differs",
    )
    require(
        sum(row.get("Action") == "pass" and "Test" not in row for row in rows) == 1, "test package completion missing"
    )
    return {"roots": sorted(roots), "passes": sorted(all_passes), "root_count": len(roots), **NO_EXECUTION}


def pe(raw):
    require(256 <= len(raw) <= 32 << 20 and raw[:2] == b"MZ", "PE byte bound refused")
    offset = struct.unpack_from("<I", raw, 60)[0]
    require(64 <= offset <= len(raw) - 264 and raw[offset : offset + 4] == b"PE\0\0", "PE header refused")
    machine, count = struct.unpack_from("<HH", raw, offset + 4)
    optional_size, flags = struct.unpack_from("<HH", raw, offset + 20)
    optional = offset + 24
    require(
        machine == 0x8664 and 1 <= count <= 32 and optional_size == 240 and not flags & 0x2000,
        "PE image identity refused",
    )
    require(
        struct.unpack_from("<H", raw, optional)[0] == 0x20B and struct.unpack_from("<H", raw, optional + 68)[0] == 3,
        "PE64 console required",
    )
    entry = struct.unpack_from("<I", raw, optional + 16)[0]
    sections, table = [], optional + optional_size
    require(table + 40 * count <= len(raw), "PE section table refused")
    executable_entry = False
    for index in range(count):
        at = table + 40 * index
        size, rva, raw_size, start = struct.unpack_from("<IIII", raw, at + 8)
        characteristics = struct.unpack_from("<I", raw, at + 36)[0]
        require(start + raw_size <= len(raw) and rva + max(size, raw_size) <= 1 << 32, "PE section bound refused")
        require(characteristics & 0xA0000000 != 0xA0000000, "writable executable section refused")
        executable_entry |= bool(characteristics & 0x20000000) and rva <= entry < rva + min(size, raw_size)
        sections.append((rva, raw_size, start))
    require(executable_entry, "PE entry not file backed executable")

    def rva_at(rva, length):
        matches = [
            start + rva - base for base, size, start in sections if base <= rva and length <= size - (rva - base)
        ]
        require(len(matches) == 1, "PE RVA refused")
        return matches[0]

    import_rva, import_size = struct.unpack_from("<II", raw, optional + 120)
    require(import_rva and 20 <= import_size <= 4096, "PE import directory refused")
    imports, terminated = [], False
    for index in range(min(import_size // 20, 128)):
        row = struct.unpack_from("<IIIII", raw, rva_at(import_rva + 20 * index, 20))
        if row == (0, 0, 0, 0, 0):
            terminated = True
            break
        at = rva_at(row[3], 1)
        end = raw.find(b"\0", at, min(at + 129, len(raw)))
        require(end > at, "PE import name bound refused")
        name = raw[at:end].decode("ascii", errors="strict")
        require(re.fullmatch(r"[A-Za-z0-9_.-]+\.dll", name, re.IGNORECASE), "PE import name refused")
        imports.append(name)
    require(
        terminated and imports and len(imports) == len(set(name.lower() for name in imports)),
        "PE import inventory refused",
    )
    return {
        "machine": "amd64",
        "format": "PE32+",
        "console": True,
        "writable_executable_sections": False,
        "import_libraries": imports,
    }


def command(argv, cwd, artifact, label, environment):
    result = subprocess.run(
        argv, cwd=cwd, env=environment, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900
    )
    require(len(result.stdout) <= 16 << 20, "command log bound refused")
    write(artifact / "logs" / (label + ".log"), result.stdout)
    require(result.returncode == 0, "fixed build command refused")
    return result.stdout


def git(checkout, *arguments):
    result = subprocess.run(["git", "-C", str(checkout), *arguments], check=True, capture_output=True, timeout=30)
    require(len(result.stdout) <= 4 << 20, "Git output refused")
    return result.stdout


def stage(checkout, source, artifact, head):
    require(git(checkout, "rev-parse", "HEAD").decode().strip() == head, "checkout identity differs")
    require(not git(checkout, "status", "--porcelain", "--untracked-files=all").strip(), "checkout must be clean")
    paths = list(ROOT_FILES)
    for root, names in DIRECTORIES.items():
        expected = sorted(root + "/" + name for name in names)
        actual = git(checkout, "ls-tree", "-r", "--name-only", head, "--", root).decode().splitlines()
        require(actual == expected, "complete source inventory differs")
        paths.extend(expected)
    require(len(paths) == len(set(paths)), "source list duplicated")
    manifest = {}
    for name in sorted(paths):
        raw = git(checkout, "cat-file", "blob", head + ":" + name)
        require(0 < len(raw) <= 2 << 20, "source byte bound refused")
        if name.endswith(".go"):
            require(
                not re.search(rb"(?m)^\s*//go:embed\b", raw) and b'"C"' not in raw and b"#cgo" not in raw,
                "local embedded or native input refused",
            )
        write(source / name, raw)
        write(artifact / "source" / name, raw)
        manifest[name] = {"sha256": sha(raw), "size": len(raw)}
    require(ordinary(source / HELPER) == ordinary(Path(__file__)), "running helper differs from exact Git source")
    return manifest


def stream_objects(raw):
    require(0 < len(raw) <= 16 << 20, "dependency metadata bound refused")
    text = raw.decode("utf-8", errors="strict")
    decoder, index, values = json.JSONDecoder(object_pairs_hook=unique_object), 0, []
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        value, index = decoder.raw_decode(text, index)
        require(type(value) is dict and len(values) < 512, "dependency package bound refused")
        values.append(value)
    return values


def closure(raw, source, artifact, local_packages, *, retain=True):
    local, inputs, packages = set(), {}, stream_objects(raw)
    for package in packages:
        require(
            not package.get("Error")
            and not package.get("DepsErrors")
            and not any(package.get(key) for key in NATIVE_FIELDS),
            "compiler input refused",
        )
        if package.get("Standard"):
            continue
        require(not package.get("EmbedFiles"), "nonstandard embed refused")
        module = package.get("Module", {})
        require(not module.get("Replace"), "replacement module refused")
        directory = Path(package["Dir"])
        if module.get("Main") is True and module.get("Path") == "github.com/defenseclaw/defenseclaw":
            relative = directory.relative_to(source).as_posix()
            require(
                relative in local_packages and package["ImportPath"] == module["Path"] + "/" + relative,
                "local package refused",
            )
            require(not package.get("SFiles") and not package.get("HFiles"), "local assembly refused")
            local.add(relative)
            continue
        require(all(module.get(key) == MODULE[key] for key in ("Path", "Version", "Sum")), "external module differs")
        for field in COMPILED_FIELDS:
            for name in package.get(field, []):
                require(Path(name).name == name and name not in (".", ".."), "dependency input name refused")
                raw_file = ordinary(directory / name)
                target = "dependencies/compiled/" + package["ImportPath"] + "/" + name
                if target in inputs:
                    require(inputs[target]["sha256"] == sha(raw_file), "dependency input differs")
                else:
                    if retain:
                        write(artifact / target, raw_file)
                    inputs[target] = {"sha256": sha(raw_file), "size": len(raw_file)}
    require(local == set(local_packages), "local compiler closure differs")
    return {
        "package_count": len(packages),
        "local_packages": sorted(local),
        "external_module": MODULE,
        "external_compiled_files": inputs,
    }


def unchanged_compiler_inputs(raw, source, artifact, local_packages, before, generated):
    require(
        closure(raw, source, artifact, local_packages, retain=False) == before,
        "selected external compiler inputs changed",
    )
    for name, expected in generated.items():
        require(ordinary(source / GENERATED / name) == expected, "generated compiler source changed")


def build():
    require(len(sys.argv) == 1, "fixed build accepts no arguments")
    require(sys.platform == "win32", "Windows host required")
    require(
        os.environ.get("GITHUB_REPOSITORY") == "cisco-ai-defense/defenseclaw"
        and os.environ.get("GITHUB_REF") == "refs/heads/codex/axis-sandbox-feasibility",
        "workflow scope refused",
    )
    head = os.environ["GITHUB_SHA"]
    require(re.fullmatch("[0-9a-f]{40}", head), "Git head refused")
    receipt = reviewed_registry(REVIEWED)  # Closed before any download or compiler invocation.
    workspace = Path(os.environ["GITHUB_WORKSPACE"])
    checkout, work, artifact = (
        workspace / "defenseclaw-source",
        workspace / "windows-harness-build",
        workspace / "windows-harness-artifact",
    )
    work.mkdir()
    artifact.mkdir()
    document(
        artifact / "WORKFLOW.json",
        {
            "repository": os.environ["GITHUB_REPOSITORY"],
            "workflow": WORKFLOW,
            "build_commit": head,
            "run_id": int(os.environ["GITHUB_RUN_ID"]),
            "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            **NO_EXECUTION,
        },
    )
    source = work / "source"
    source.mkdir()
    sources = stage(checkout, source, artifact, head)
    environment = {
        key: os.environ[key]
        for key in (
            "PATH",
            "SystemRoot",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
        )
        if key in os.environ
    }
    environment.update(
        GOTOOLCHAIN="local",
        CGO_ENABLED="0",
        GOOS="windows",
        GOARCH="amd64",
        GOAMD64="v1",
        GOWORK="off",
        GOENV="off",
        GOFLAGS="",
        GOEXPERIMENT="",
        GODEBUG="",
        GOPROXY="https://proxy.golang.org",
        GOSUMDB="sum.golang.org",
        GOPRIVATE="",
        GONOPROXY="",
        GONOSUMDB="",
        GOMODCACHE=str(work / "modules"),
        GOCACHE=str(work / "cache-tests"),
    )
    toolchain_raw = command(
        [
            "go",
            "env",
            "-json",
            "GOVERSION",
            "GOOS",
            "GOARCH",
            "GOAMD64",
            "CGO_ENABLED",
            "GOTOOLCHAIN",
            "GOROOT",
            "GOTOOLDIR",
            "GOWORK",
            "GOENV",
            "GOFLAGS",
            "GOEXPERIMENT",
        ],
        source,
        artifact,
        "toolchain",
        environment,
    )
    toolchain = json.loads(toolchain_raw)
    expected = {
        "GOVERSION": "go1.26.5",
        "GOOS": "windows",
        "GOARCH": "amd64",
        "GOAMD64": "v1",
        "CGO_ENABLED": "0",
        "GOTOOLCHAIN": "local",
        "GOWORK": "off",
        "GOENV": "",
        "GOFLAGS": "",
        "GOEXPERIMENT": "",
    }
    require(all(toolchain.get(key) == value for key, value in expected.items()), "Go toolchain differs")
    document(artifact / "TOOLCHAIN.json", toolchain)
    module = json.loads(
        command(
            ["go", "mod", "download", "-json", "golang.org/x/sys@v0.47.0"],
            source,
            artifact,
            "module-download",
            environment,
        )
    )
    require(
        not module.get("Error") and all(module.get(key) == value for key, value in MODULE.items()),
        "module checksum differs",
    )
    verification = work / "dependency-verifier"
    verification.mkdir()
    sums = (
        "golang.org/x/sys v0.47.0 " + MODULE["Sum"] + "\ngolang.org/x/sys v0.47.0/go.mod " + MODULE["GoModSum"] + "\n"
    )
    require(
        set(sums.splitlines()).issubset(set(ordinary(source / "go.sum").decode().splitlines())),
        "source checksums differ",
    )
    write(
        verification / "go.mod",
        b"module example.invalid/axis-windows-harness-verifier\n\ngo 1.26.5\n\nrequire golang.org/x/sys v0.47.0\n",
    )
    write(verification / "go.sum", sums.encode())
    require(
        command(["go", "mod", "verify"], verification, artifact, "module-verify", environment)
        == b"all modules verified\n",
        "module cache verification failed",
    )
    for key, name, bound in (
        ("Zip", "golang.org-x-sys-v0.47.0.zip", 16 << 20),
        ("GoMod", "golang.org-x-sys-go.mod", 1 << 20),
    ):
        write(artifact / "dependencies" / name, ordinary(Path(module[key]), bound))
    write(artifact / "dependencies" / "golang.org-x-sys-LICENSE", ordinary(Path(module["Dir"]) / "LICENSE"))
    dependencies_raw = command(
        ["go", "list", "-mod=readonly", "-deps", "-json", "./" + HARNESS], source, artifact, "go-deps", environment
    )
    dependencies = closure(dependencies_raw, source, artifact, LOCAL_PACKAGES)
    document(artifact / "DEPENDENCY-CLOSURE.json", dependencies)
    test_results = {}
    for index, (package, names) in enumerate(TESTS.items()):
        require(names, "test selection closed")
        raw = command(
            [
                "go",
                "test",
                "-mod=readonly",
                "-p",
                "1",
                "-json",
                "./" + package,
                "-run",
                "^(" + "|".join(names) + ")$",
                "-count=1",
                "-timeout=30s",
            ],
            source,
            artifact,
            "pure-tests-" + str(index),
            environment,
        )
        test_results[package] = passed_tests(raw, names)
    document(artifact / "PURE-TESTS.json", test_results)
    generated_main, generated_receipt, delta = pin_main(ordinary(source / HARNESS / "main_windows.go"), REVIEWED)
    require(generated_receipt == receipt, "receipt changed")
    run = ordinary(source / HARNESS / "run_windows.go")
    for name, raw in (("main_windows.go", generated_main), ("run_windows.go", run)):
        write(source / GENERATED / name, raw)
        write(artifact / "generated-source" / name, raw)
    write(artifact / "REVIEWED-ARTIFACTS.json", receipt)
    document(
        artifact / "GENERATED-DELTA.json",
        {
            "base_main_sha256": sha(ordinary(source / HARNESS / "main_windows.go")),
            "generated_main_sha256": sha(generated_main),
            "run_unchanged_sha256": sha(run),
            "receipt_sha256": sha(receipt),
            "source_path": GENERATED,
            **delta,
        },
    )
    images = []
    for index in (1, 2):
        image = work / ("harness-" + str(index) + ".exe")
        build_env = {**environment, "GOCACHE": str(work / ("cache-build-" + str(index)))}
        command(
            [
                "go",
                "build",
                "-mod=readonly",
                "-trimpath",
                "-buildvcs=false",
                "-ldflags=-w -s -buildid=",
                "-p",
                "1",
                "-o",
                str(image),
                "./" + GENERATED,
            ],
            source,
            artifact,
            "build-" + str(index),
            build_env,
        )
        images.append(ordinary(image, 32 << 20))
    require(images[0] == images[1], "independent cache builds differ")
    pe_metadata = pe(images[0])
    image_path = artifact / "bin" / "fixed-windows-harness.exe"
    write(image_path, images[0])
    buildinfo = command(["go", "version", "-m", str(image_path)], source, artifact, "buildinfo", environment)
    write(artifact / "GO-BUILDINFO.txt", buildinfo)
    lines = buildinfo.decode().splitlines()
    require(
        [line.strip().split() for line in lines if line.startswith("\tdep\t")]
        == [["dep", MODULE["Path"], MODULE["Version"], MODULE["Sum"]]]
        and not any(line.startswith("\t=>") for line in lines),
        "image module buildinfo differs",
    )
    require("\tpath\tgithub.com/defenseclaw/defenseclaw/" + GENERATED in lines, "generated image package differs")
    for name, entry in sources.items():
        require(sha(ordinary(source / name)) == entry["sha256"], "canonical staged source changed")
    require(
        command(["go", "mod", "verify"], verification, artifact, "module-verify-after", environment)
        == b"all modules verified\n",
        "after-build module cache verification failed",
    )
    unchanged_compiler_inputs(
        dependencies_raw,
        source,
        artifact,
        LOCAL_PACKAGES,
        dependencies,
        {"main_windows.go": generated_main, "run_windows.go": run},
    )
    document(
        artifact / "BUILD-RESULT.json",
        {
            "image_sha256": sha(images[0]),
            "image_size": len(images[0]),
            "receipt_sha256": sha(receipt),
            "receipt_size": len(receipt),
            "generated_source_sha256": {"main_windows.go": sha(generated_main), "run_windows.go": sha(run)},
            "two_independent_caches_byte_identical": True,
            "external_module_cache_verified_before_and_after": True,
            "selected_external_compiler_inputs_unchanged_after_build": True,
            "generated_sources_unchanged_after_build": True,
            **NO_EXECUTION,
        },
    )
    tools = {"go": Path(toolchain["GOROOT"]) / "bin/go.exe"}
    tools.update({name: Path(toolchain["GOTOOLDIR"]) / (name + ".exe") for name in ("compile", "link", "asm")})
    tool_hashes = {name: sha(ordinary(path, 128 << 20)) for name, path in tools.items()}
    files = {}
    total = 0
    for path in sorted(artifact.rglob("*")):
        if path.is_dir():
            continue
        raw = ordinary(path, 32 << 20)
        total += len(raw)
        require(total <= 128 << 20, "artifact aggregate refused")
        files[path.relative_to(artifact).as_posix()] = {"sha256": sha(raw), "size": len(raw)}
    document(
        artifact / "PROVENANCE.json",
        {
            "scope": "fixed_windows_token_probe_harness_build_only",
            "repository": os.environ["GITHUB_REPOSITORY"],
            "workflow": WORKFLOW,
            "build_commit": head,
            "run_id": int(os.environ["GITHUB_RUN_ID"]),
            "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "source_files": sources,
            "files": files,
            "tool_sha256": tool_hashes,
            "go_version": "go1.26.5",
            "peer_and_payload_are_receipt_pins_only": True,
            "canonical_registry_closed": True,
            "generated_registry_enabled": True,
            "two_independent_caches_byte_identical": True,
            "receipt_sha256": sha(receipt),
            "selected_tests": test_results,
            "pe": pe_metadata,
            **NO_EXECUTION,
        },
    )


if __name__ == "__main__":
    try:
        build()
    except Exception:
        raise SystemExit("fixed Windows harness build refused") from None
    print("fixed Windows harness build completed; no image executed")
