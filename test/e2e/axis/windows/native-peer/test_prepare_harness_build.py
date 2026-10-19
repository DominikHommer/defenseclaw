# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Pure build-contract tests: no compiler, Windows API, image or process launch."""

import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "fixed_windows_build", Path(__file__).with_name("prepare_harness_build.py")
)
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def literal():
    peer, payload = "a" * 64, "b" * 64
    receipt = {
        "production_qualification": False,
        "peer": {"image_sha256": peer, "size": 1234},
        "payload": {"image_sha256": payload, "size": 2345},
    }
    return {
        "receipt_utf8": json.dumps(receipt),
        "peer_sha256": peer,
        "peer_size": 1234,
        "payload_sha256": payload,
        "payload_size": 2345,
    }


class BuildContractTests(unittest.TestCase):
    def test_closed_slots_refuse_before_any_builder(self):
        for value in (None, {}, [], "input", {**literal(), "override": "runtime"}):
            with self.assertRaises(ValueError):
                BUILD.reviewed_registry(value)

    def test_receipt_images_sizes_scope_and_ambiguous_json_are_bound(self):
        valid = literal()
        self.assertEqual(BUILD.reviewed_registry(valid), valid["receipt_utf8"].encode())
        for key, value in (
            ("peer_sha256", "A" * 64),
            ("payload_sha256", "../x"),
            ("peer_size", True),
            ("payload_size", 64 << 20 | 1),
        ):
            with self.assertRaises(ValueError):
                BUILD.reviewed_registry({**valid, key: value})
        for alter in (
            lambda value: value["peer"].update(size=999),
            lambda value: value["payload"].update(image_sha256="c" * 64),
            lambda value: value.update(production_qualification=True),
        ):
            receipt = json.loads(valid["receipt_utf8"])
            alter(receipt)
            with self.assertRaises(ValueError):
                BUILD.reviewed_registry({**valid, "receipt_utf8": json.dumps(receipt)})
        for raw in ('{"peer":{},"peer":{}}', valid["receipt_utf8"] + "{}"):
            with self.assertRaises(ValueError):
                BUILD.reviewed_registry({**valid, "receipt_utf8": raw})

    def test_generated_delta_preserves_every_other_byte_including_unicode(self):
        raw = "before λ-雪\nvar reviewed = artifactRegistry{}\nafter\n".encode()
        pinned, receipt, delta = BUILD.pin_main(raw, literal())
        self.assertEqual(pinned.replace(delta["enabled"].encode(), delta["closed"].encode(), 1), raw)
        self.assertIn(('Receipt: "' + BUILD.sha(receipt) + '"').encode(), pinned)
        for changed in (raw.replace(b"var reviewed", b"var other"), raw + raw):
            with self.assertRaises(ValueError):
                BUILD.pin_main(changed, literal())

    def test_exact_test_roots_cannot_pass_on_skip_duplicate_or_missing_package(self):
        expected = ("TestOne", "TestTwo")
        rows = [{"Action": "pass", "Test": name} for name in ("TestOne/a", *expected)] + [{"Action": "pass"}]

        def raw(values):
            return b"\n".join(json.dumps(row).encode() for row in values)

        self.assertEqual(BUILD.passed_tests(raw(rows), expected)["root_count"], 2)
        for values in (
            rows[:-1],
            rows + [rows[0]],
            rows + [{"Action": "skip", "Test": "TestOther"}],
            rows + [{"Action": "fail"}],
            rows + [{"Action": "pass", "Test": "TestOther"}],
            rows[2:],
        ):
            with self.assertRaises(ValueError):
                BUILD.passed_tests(raw(values), expected)

    def test_dependency_stream_rejects_ambiguity_trailing_data_and_excess_packages(self):
        self.assertEqual(
            BUILD.stream_objects(b'{"Standard":true}\n {"Standard":false}'), [{"Standard": True}, {"Standard": False}]
        )
        for raw in (b'{"Standard":true,"Standard":false}', b"{} trailing", b"[]", b"{}" * 513):
            with self.assertRaises(ValueError):
                BUILD.stream_objects(raw)

    def test_pe_requires_console_non_writable_code_entry_and_bounded_imports(self):
        raw = bytearray(2048)
        raw[:2] = b"MZ"
        struct.pack_into("<I", raw, 60, 128)
        raw[128:132] = b"PE\0\0"
        struct.pack_into("<HH", raw, 132, 0x8664, 1)
        struct.pack_into("<HH", raw, 148, 240, 2)
        optional = 152
        struct.pack_into("<H", raw, optional, 0x20B)
        struct.pack_into("<I", raw, optional + 16, 0x1000)
        struct.pack_into("<H", raw, optional + 68, 3)
        struct.pack_into("<II", raw, optional + 120, 0x1100, 40)
        struct.pack_into("<IIII", raw, optional + 240 + 8, 1024, 0x1000, 1024, 512)
        struct.pack_into("<I", raw, optional + 240 + 36, 0x60000020)
        struct.pack_into("<IIIII", raw, 768, 0x1180, 0, 0, 0x1150, 0x1180)
        raw[848:861] = b"KERNEL32.dll\0"
        self.assertEqual(BUILD.pe(bytes(raw))["import_libraries"], ["KERNEL32.dll"])
        for at, fmt, value in (
            (optional + 68, "<H", 2),
            (optional + 240 + 36, "<I", 0xE0000020),
            (optional + 16, "<I", 0x3000),
            (optional + 120, "<I", 0x9000),
        ):
            changed = bytearray(raw)
            struct.pack_into(fmt, changed, at, value)
            with self.assertRaises(ValueError):
                BUILD.pe(bytes(changed))

    def test_source_inventories_and_pure_selections_are_closed_and_unique(self):
        names = [root + "/" + name for root, entries in BUILD.DIRECTORIES.items() for name in entries] + list(
            BUILD.ROOT_FILES
        )
        self.assertEqual(len(names), len(set(names)))
        self.assertIn(BUILD.HELPER, names)
        self.assertIn(BUILD.HELPER_TEST, names)
        self.assertEqual(len(BUILD.TESTS[BUILD.HARNESS]), 8)
        self.assertEqual(len(BUILD.TESTS[BUILD.PAYLOAD]), 1)
        self.assertGreater(len(BUILD.TESTS[BUILD.PROTO]), 10)
        self.assertEqual(
            set(BUILD.TESTS[BUILD.HARNESS]),
            {
                "TestFixedCanaryProtocolRequiresExactStreamsExitBindingAndDestroy",
                "TestFixedCanaryRegistryIsClosedAndWindowsPlanIsExplicit",
                "TestFixedFailureDiagnosticsPreserveJoinedClassesAndNeverFormatRawErrors",
                "TestFixedFailureDiagnosticRefusesUnrecognizedNativeStartStages",
                "TestFixedProtocolFailureDiagnosticsRequireValidatedCorrelationAndRedactCauses",
                "TestFixedPreparationDiagnosticRequiresCorrelatedValidatedFailure",
                "TestFixedTokenFactsAreReportedOnlyAfterCorrelatedStarted",
                "TestFixedNativeSignalDiagnosticRetainsBothClosedRolesOnlyAtSignalStage",
            },
        )
        self.assertEqual(
            BUILD.TESTS[BUILD.PAYLOAD], ("TestFixedPrivateInputFrameRefusesTruncationExtraTargetAndMissingPort",)
        )
        for package, tests in BUILD.TESTS.items():
            self.assertEqual(len(tests), len(set(tests)))
            self.assertIn(package, (BUILD.HARNESS, BUILD.PAYLOAD, BUILD.PROTO))
        self.assertEqual(
            set(BUILD.TESTS[BUILD.PROTO]),
            {
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
            },
        )

    def test_after_build_gate_refuses_external_or_generated_mutation_without_retaining_again(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, external, artifact = root / "source", root / "external", root / "artifact"
            (source / BUILD.GENERATED).mkdir(parents=True)
            external.mkdir()
            (external / "fixed.go").write_bytes(b"fixed external source")
            generated = {"main_windows.go": b"fixed main", "run_windows.go": b"fixed run"}
            for name, raw in generated.items():
                (source / BUILD.GENERATED / name).write_bytes(raw)
            packages = [
                {
                    "Dir": str(source / "local"),
                    "ImportPath": "github.com/defenseclaw/defenseclaw/local",
                    "Module": {"Main": True, "Path": "github.com/defenseclaw/defenseclaw"},
                },
                {
                    "Dir": str(external),
                    "ImportPath": "golang.org/x/sys/windows",
                    "Module": BUILD.MODULE,
                    "GoFiles": ["fixed.go"],
                },
            ]
            raw = b"\n".join(json.dumps(package).encode() for package in packages)
            before = BUILD.closure(raw, source, artifact, {"local"}, retain=False)
            BUILD.unchanged_compiler_inputs(raw, source, artifact, {"local"}, before, generated)
            self.assertFalse(artifact.exists())
            (external / "fixed.go").write_bytes(b"changed external source")
            with self.assertRaises(ValueError):
                BUILD.unchanged_compiler_inputs(raw, source, artifact, {"local"}, before, generated)
            (external / "fixed.go").write_bytes(b"fixed external source")
            (source / BUILD.GENERATED / "main_windows.go").write_bytes(b"changed generated source")
            with self.assertRaises(ValueError):
                BUILD.unchanged_compiler_inputs(raw, source, artifact, {"local"}, before, generated)


if __name__ == "__main__":
    unittest.main()
