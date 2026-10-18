# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Pure observation checks; these never launch a probe or a custody wrapper."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("windows_psec_live", Path(__file__).with_name("run_live.py"))
assert _SPEC is not None and _SPEC.loader is not None
live = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(live)


class ObservationTests(unittest.TestCase):
    def setUp(self) -> None:
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

    def test_complete_fixed_observations_accepted(self) -> None:
        self.assertTrue(live.valid_observations(self.record, self.receipt))

    def test_job_empty_or_pre_resume_assignment_missing_refused(self) -> None:
        for name in ("outer_job_empty", "assigned_before_resume"):
            with self.subTest(name=name):
                changed = {**self.record, name: False}
                self.assertFalse(live.valid_observations(changed, self.receipt))

    def test_boolean_is_not_zero_exit_or_active_count(self) -> None:
        for name in ("exit_code", "outer_job_active_before_final_cleanup"):
            with self.subTest(name=name):
                self.assertFalse(live.valid_observations({**self.record, name: False}, self.receipt))

    def test_diagnostic_without_actual_payload_marker_refused(self) -> None:
        changed = copy.deepcopy(self.record)
        values = [json.loads(line) for line in changed["stdout"].splitlines()]
        values[0]["stdout"] = ""
        changed["stdout"] = "\n".join(json.dumps(value) for value in values)
        self.assertFalse(live.valid_observations(changed, self.receipt))

    def test_missing_check_refused(self) -> None:
        changed = copy.deepcopy(self.record)
        values = [json.loads(line) for line in changed["stdout"].splitlines()]
        values[1]["checks"].pop()
        changed["stdout"] = "\n".join(json.dumps(value) for value in values)
        self.assertFalse(live.valid_observations(changed, self.receipt))

    def test_nine_boundary_checks_cannot_certify_loader_diagnostic(self) -> None:
        changed = copy.deepcopy(self.record)
        values = [json.loads(line) for line in changed["stdout"].splitlines()]
        values[1]["checks"] = [
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
        self.assertFalse(live.valid_observations(changed, self.receipt))


if __name__ == "__main__":
    unittest.main()
