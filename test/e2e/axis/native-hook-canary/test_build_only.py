# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Pure recipe tests: temporary public text only, no Go/native/network calls."""

import ast
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("fixed_build", Path(__file__).with_name("build_only.py"))
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class FixedBuildTests(unittest.TestCase):
    def test_pin_generation_is_closed_and_exact(self):
        template = b'package gateway\nconst containedPayloadSHA = ""\n'
        digest = "b" * 64
        self.assertEqual(
            BUILD.generated_pin(template, digest),
            b'package gateway\nconst containedPayloadSHA = "sha256:' + digest.encode() + b'"\n',
        )
        for raw, value in (
            (template * 2, digest),
            (template.replace(b'""', b'"old"'), digest),
            (template, "sha256:" + digest),
            (template, "B" * 64),
            (template, "x"),
        ):
            with self.subTest(raw=raw, digest=value), self.assertRaises(BUILD.RefusedError):
                BUILD.generated_pin(raw, value)

    def test_exact_host_log_rejects_missing_skipped_failed_and_native(self):
        root = BUILD.SAFE_TESTS[2][2]
        names = [root, *(root + "/" + child for child in BUILD.CONNECTORS)]

        def log(entries):
            return b"".join(json.dumps(item).encode() + b"\n" for item in entries)

        entries = [{"Action": "pass", "Test": name} for name in names] + [{"Action": "pass"}]
        self.assertEqual(len(BUILD.check_test_log(log(entries), root, BUILD.CONNECTORS)), 13)
        variants = (
            entries[:-2] + entries[-1:],
            entries + [{"Action": "skip"}],
            entries + [{"Action": "fail"}],
            entries + [entries[0]],
            entries + [{"Action": "run", "Test": "TestContainedNativeHookClaudeUsesActualSharedEvaluator"}],
        )
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(BUILD.RefusedError):
                BUILD.check_test_log(log(changed), root, BUILD.CONNECTORS)

    def test_fixed_source_staging_rejects_mutation_and_no_pin_override(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            # Exercise actual fixed pins with synthetic size/hash-matching bytes
            # only by selecting a temporary test map; public API accepts no map.
            original = BUILD.PINS
            try:
                BUILD.PINS = {f"input-{number}.go": {"sha256": BUILD.sha(b"fixed"), "bytes": 5} for number in range(19)}
                for name in BUILD.PINS:
                    (base / name).write_bytes(b"fixed")
                self.assertEqual(len(BUILD.checked_sources(base)), 19)
                (base / "input-0.go").write_bytes(b"other")
                with self.assertRaises(BUILD.RefusedError):
                    BUILD.checked_sources(base)
                (base / "input-0.go").unlink()
                with self.assertRaises(OSError):
                    BUILD.checked_sources(base)
            finally:
                BUILD.PINS = original

    def test_safe_selectors_are_exact_host_tests(self):
        self.assertEqual(len(BUILD.SAFE_TESTS), 4)
        self.assertEqual(
            {item[2] for item in BUILD.SAFE_TESTS},
            {
                "TestFixedHookSchemasAreClosedAndCommandsStayJSON",
                "TestFixedHookExchangeUsesExistingNativeClientWithoutOverride",
                "TestFixedContainedHookSharedEvaluatorOracleWithoutNative",
                "TestFixedContainedHookCleanupRetainsUncertainOwnerWithoutNative",
            },
        )
        source = Path(__file__).with_name("build_only.py").read_text()
        self.assertNotIn('"ldd"', source)
        self.assertNotIn('str(driver), "-test.run"', source)

    def test_build_calls_only_host_go_readers_compilers_and_explicit_test_selectors(self):
        # Check actual fixed argv construction, not a separate command list.
        source = Path(__file__).with_name("build_only.py").read_text()
        tree = ast.parse(source)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "run"
        ]
        self.assertGreater(len(calls), 8)
        for call in calls:
            argv = call.args[0]
            self.assertIsInstance(argv, ast.List)
            self.assertIsInstance(argv.elts[0], ast.Name)
            self.assertEqual(argv.elts[0].id, "go")
            verb = ast.literal_eval(argv.elts[1])
            self.assertIn(verb, {"test", "build", "version", "mod", "list"})
            constants = {item.value for item in argv.elts if isinstance(item, ast.Constant)}
            if verb == "test":
                self.assertTrue("-c" in constants or "-run" in constants)
            if any(
                isinstance(item, ast.Call)
                and isinstance(item.func, ast.Name)
                and item.func.id == "str"
                and isinstance(item.args[0], ast.Name)
                and item.args[0].id == "driver"
                for item in argv.elts
            ):
                self.assertTrue("-c" in constants or verb == "version")


if __name__ == "__main__":
    unittest.main()
