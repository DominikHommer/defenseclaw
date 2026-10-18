# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Pure observation checks; these never launch a probe or a custody wrapper."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location("windows_psec_live", Path(__file__).with_name("run_live.py"))
assert _SPEC is not None and _SPEC.loader is not None
live = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(live)


class ObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mode = "loader-only"
        self.receipt = {
            "binary_sha256": "b" * 64,
            "build_commit": "a" * 40,
            "build_run": 123,
            "artifact_id": 456,
            "combined_lock_sha256": "c" * 64,
        }
        cases = [
            {"case": mode, "outcome": outcome, "direct_handle_signaled": True, "stdout": marker, "stderr": ""}
            for mode, outcome, marker in [
                ("loader", "Exited(23)", "FIXED_PSEC_LOADER_STARTED\n"),
            ]
        ]
        cases.append(
            {
                "axis_commit": live.artifact_verifier.AXIS_COMMIT,
                "mxc_commit": live.artifact_verifier.MXC_COMMIT,
                "translation_contract": "fixed-axis-hard-block-to-mxc-typed-1.0.0",
                "backend": "native_windows_psec_only",
                "production_qualification": False,
                "loader_only_diagnostic": True,
                "checks": sorted(live.CHECKS),
            }
        )
        self.record = {
            **self.receipt,
            "passed": True,
            "production_certification": False,
            "scope": live.artifact_verifier.SCOPE,
            "variant": live.artifact_verifier.VARIANT,
            "mode": "loader-only",
            "exit_code": 0,
            "outer_job_active_before_final_cleanup": 0,
            "outer_job_empty": True,
            "assigned_before_resume": True,
            "stdout": "\n".join(json.dumps(value) for value in cases),
        }

    def validate(self, record: object) -> bool:
        return live.valid_observations(record, self.receipt, self.mode)

    def test_complete_fixed_observations_accepted(self) -> None:
        self.assertTrue(self.validate(self.record))

    def test_job_empty_or_pre_resume_assignment_missing_refused(self) -> None:
        for name in ("outer_job_empty", "assigned_before_resume"):
            with self.subTest(name=name):
                changed = {**self.record, name: False}
                self.assertFalse(self.validate(changed))

    def test_boolean_is_not_zero_exit_or_active_count(self) -> None:
        for name in ("exit_code", "outer_job_active_before_final_cleanup"):
            with self.subTest(name=name):
                self.assertFalse(self.validate({**self.record, name: False}))

    def test_diagnostic_without_actual_payload_marker_refused(self) -> None:
        changed = copy.deepcopy(self.record)
        values = [json.loads(line) for line in changed["stdout"].splitlines()]
        values[0]["stdout"] = ""
        changed["stdout"] = "\n".join(json.dumps(value) for value in values)
        self.assertFalse(self.validate(changed))

    def test_missing_check_refused(self) -> None:
        changed = copy.deepcopy(self.record)
        values = [json.loads(line) for line in changed["stdout"].splitlines()]
        values[-1]["checks"].pop()
        changed["stdout"] = "\n".join(json.dumps(value) for value in values)
        self.assertFalse(self.validate(changed))

    def test_wrong_or_incomplete_check_set_refused(self) -> None:
        changed = copy.deepcopy(self.record)
        values = [json.loads(line) for line in changed["stdout"].splitlines()]
        values[-1]["checks"] = [
            "private_environment",
            "allowed_write",
            "outside_read_write_denied",
            "readonly_write_denied",
            "loopback_ipv4_ipv6_tcp_udp",
            "exit23",
            "timeout",
            "retained_direct_process_handles_signaled",
            "owned_fixture_removed",
        ]
        changed["stdout"] = "\n".join(json.dumps(value) for value in values)
        self.assertFalse(self.validate(changed))


class BoundaryObservationTests(ObservationTests):
    def setUp(self) -> None:
        super().setUp()
        self.mode = "standalone-boundary"
        cases = [
            {"case": case, "outcome": outcome, "direct_handle_signaled": True, "stdout": marker, "stderr": ""}
            for case, outcome, marker in [
                ("argv", "Exited(0)", "FIXED_ARGV_PASS\n"),
                ("boundary", "Exited(0)", "FIXED_BOUNDARIES_PASS\n"),
                ("exit23", "Exited(23)", "FIXED_EXIT23_STARTED\n"),
                ("timeout", "TimedOut", "FIXED_TIMEOUT_STARTED\n"),
            ]
        ]
        final = json.loads(self.record["stdout"].splitlines()[-1])
        final["loader_only_diagnostic"] = False
        final["checks"] = sorted(live.BOUNDARY_CHECKS)
        cases.append(final)
        self.record.update(
            scope=live.artifact_verifier.BOUNDARY_SCOPE,
            variant=live.artifact_verifier.BOUNDARY_VARIANT,
            mode=self.mode,
            stdout="\n".join(json.dumps(case) for case in cases),
        )

    def test_boundary_transcript_cannot_certify_loader_mode(self) -> None:
        self.assertFalse(live.valid_observations(self.record, self.receipt, "loader-only"))

    def test_every_fixed_payload_marker_and_typed_timeout_is_required(self) -> None:
        for index in range(4):
            with self.subTest(index=index):
                cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
                cases[index]["stdout"] = ""
                changed = {**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)}
                self.assertFalse(self.validate(changed))
        cases = [json.loads(line) for line in self.record["stdout"].splitlines()]
        cases[3]["outcome"] = "Exited(124)"
        self.assertFalse(self.validate({**self.record, "stdout": "\n".join(json.dumps(case) for case in cases)}))


class BoundedCleanupTests(unittest.TestCase):
    def test_failed_poll_kill_and_second_wait_are_recorded_without_raising(self) -> None:
        process = mock.Mock()
        process.poll.side_effect = OSError("synthetic poll failure")
        process.kill.side_effect = OSError("synthetic kill failure")
        process.wait.side_effect = subprocess.TimeoutExpired("fixed", 5)
        errors = []
        self.assertIsNone(live.stop_owned(process, errors))
        self.assertEqual(len(errors), 3)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)

    def test_stopped_owned_process_needs_no_kill(self) -> None:
        process = mock.Mock()
        process.poll.return_value = 7
        errors = []
        self.assertEqual(live.stop_owned(process, errors), 7)
        self.assertEqual(errors, [])
        process.kill.assert_not_called()

    def test_close_failure_is_retained_and_live_reader_is_never_closed(self) -> None:
        stream, reader = mock.Mock(), mock.Mock()
        reader.is_alive.return_value = True
        errors = []
        live.close_finished_stream(stream, reader, errors)
        stream.close.assert_not_called()
        reader.is_alive.return_value = False
        stream.close.side_effect = OSError("synthetic close failure")
        live.close_finished_stream(stream, reader, errors)
        self.assertEqual(errors, ["custody stream close failed: OSError"])


class CustodyPinTests(unittest.TestCase):
    def test_hash_mismatch_closes_the_held_image_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic-not-a-pe.bin"
            path.write_bytes(b"fixed synthetic image")
            source = path.open("rb")
            with mock.patch.object(live, "open_custody_pin", return_value=source):
                with self.assertRaisesRegex(ValueError, "custody binary differs"):
                    live.pin_custody(path, "0" * 64)
            self.assertTrue(source.closed)

    def test_oversize_image_is_closed_without_hashing_or_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic-not-a-pe.bin"
            path.write_bytes(b"fixed synthetic image")
            source = path.open("rb")
            metadata = mock.Mock(st_mode=live.stat.S_IFREG, st_size=live.artifact_verifier.MAX_FILE_BYTES + 1)
            with (
                mock.patch.object(live, "open_custody_pin", return_value=source),
                mock.patch.object(live.os, "fstat", return_value=metadata),
            ):
                with self.assertRaisesRegex(ValueError, "image type or size differs"):
                    live.pin_custody(path, "0" * 64)
            self.assertTrue(source.closed)

    @unittest.skipUnless(live.sys.platform == "win32", "native Windows file sharing fixture")
    def test_mocked_launch_and_wait_keep_the_verified_wrapper_pinned(self) -> None:
        # This is an inert byte file. Popen is mocked: no PE or process executes.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            custody = root / "synthetic-not-a-pe.bin"
            image = b"fixed public synthetic wrapper bytes"
            custody.write_bytes(image)
            receipt = root / "receipt.json"
            raw = json.dumps(
                {
                    "verified": True,
                    "execution_performed": False,
                    "variant": live.artifact_verifier.VARIANT,
                    "scope": live.artifact_verifier.SCOPE,
                }
            ).encode()
            receipt.write_bytes(raw)
            process = mock.Mock(stdout=io.BytesIO(b"{}"), stderr=io.BytesIO(b""))

            def held(*_args, **_kwargs):
                with self.assertRaises(PermissionError):
                    custody.write_bytes(b"replacement")
                with self.assertRaises(PermissionError):
                    custody.rename(root / "replacement.bin")
                return process

            def wait(*_args, **_kwargs):
                held()
                return 0

            process.wait.side_effect = wait
            argv = [
                "run_live.py",
                "--loader-only",
                "--custody",
                str(custody),
                "--custody-sha256",
                hashlib.sha256(image).hexdigest(),
                "--receipt",
                str(receipt),
                "--receipt-sha256",
                hashlib.sha256(raw).hexdigest(),
                "--evidence",
                str(root / "evidence"),
            ]
            with (
                mock.patch.object(live.sys, "argv", argv),
                mock.patch.object(live.platform, "machine", return_value="AMD64"),
                mock.patch.dict(live.os.environ, {"SYSTEMROOT": str(root)}, clear=True),
                mock.patch.object(live.subprocess, "Popen", side_effect=held) as launch,
                mock.patch.object(live, "valid_observations", return_value=True),
                mock.patch("builtins.print"),
            ):
                live.main()
            launch.assert_called_once()
            process.wait.assert_called_once_with(timeout=55)
            custody.write_bytes(b"pin released after bounded wait")
            result = json.loads((root / "evidence" / "live-result.json").read_text())
            self.assertTrue(result["passed"])


if __name__ == "__main__":
    unittest.main()
