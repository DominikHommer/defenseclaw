# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""until 1.1: status and doctor show the manual cleanup a removed connector left.

The gateway (internal/gateway/connector/removed.go) records it in
``<data_dir>/removed_connector_cleanup/<connector>.json`` when it cannot prove
a file is exactly as an older DefenseClaw setup wrote it.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw import removed_connectors
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.commands.cmd_doctor import _check_removed_connector_cleanup, _DoctorResult
from defenseclaw.commands.cmd_status import status as status_cmd

from tests.helpers import cleanup_app, make_app_context

_CONFIG = "/home/u/.omnigent/config.yaml"
_STEP = "remove defenseclaw_omnigent_policy from policy_modules"
_FINISH = "defenseclaw-gateway connector teardown --connector omnigent"


def _write_record(data_dir: str, body) -> str:
    path = os.path.join(data_dir, removed_connectors.CLEANUP_DIR, "omnigent.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body if isinstance(body, str) else json.dumps(body))
    return path


_RECORD = {
    "version": 1,
    "connector": "omnigent",
    "label": "OmniGent",
    "items": [{"path": _CONFIG, "reason": "it changed after DefenseClaw wrote it", "step": _STEP}],
    "finish": _FINISH,
}


class PendingCleanupTests(unittest.TestCase):
    def test_reads_the_gateway_record(self):
        with tempfile.TemporaryDirectory() as data_dir:
            record = _write_record(data_dir, _RECORD)
            [pending] = removed_connectors.pending_cleanup(data_dir)
        self.assertEqual(
            (pending.connector, pending.label, pending.record, pending.finish),
            ("omnigent", "OmniGent", record, _FINISH),
        )
        self.assertEqual([(i.path, i.step) for i in pending.items], [(_CONFIG, _STEP)])
        self.assertEqual(pending.as_json()["items"][0]["path"], _CONFIG)

    def test_no_record_is_nothing_pending(self):
        with tempfile.TemporaryDirectory() as data_dir:
            self.assertEqual(removed_connectors.pending_cleanup(data_dir), [])
        self.assertEqual(removed_connectors.pending_cleanup(""), [])

    def test_unreadable_record_is_reported_not_hidden(self):
        with tempfile.TemporaryDirectory() as data_dir:
            _write_record(data_dir, "{not json")
            [pending] = removed_connectors.pending_cleanup(data_dir)
        self.assertIn("could not read", pending.error)
        self.assertEqual(pending.finish, _FINISH)


class DoctorTests(unittest.TestCase):
    def test_warns_with_each_step_and_the_finish_command(self):
        with tempfile.TemporaryDirectory() as data_dir:
            _write_record(data_dir, _RECORD)
            result = _DoctorResult()
            with patch.object(cmd_doctor, "_json_mode", True):
                _check_removed_connector_cleanup(SimpleNamespace(data_dir=data_dir), result)
        [check] = result.checks
        self.assertEqual(check["status"], "warn")
        self.assertIn("OmniGent", check["label"])
        self.assertIn(_CONFIG, check["detail"])
        self.assertIn(_STEP, check["detail"])
        self.assertIn(_FINISH, json.dumps(check))

    def test_prints_no_row_without_a_record(self):
        with tempfile.TemporaryDirectory() as data_dir:
            result = _DoctorResult()
            _check_removed_connector_cleanup(SimpleNamespace(data_dir=data_dir), result)
        self.assertEqual(result.checks, [])


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.data_dir = ""
        self.pending = removed_connectors.PendingCleanup(
            "omnigent",
            "OmniGent",
            "/data/removed_connector_cleanup/omnigent.json",
            _FINISH,
            (removed_connectors.CleanupItem(_CONFIG, "it changed after DefenseClaw wrote it", _STEP),),
        )

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _invoke(self, *args, pending=()):
        with (
            patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=None),
            patch.object(removed_connectors, "pending_cleanup", return_value=list(pending)),
        ):
            return CliRunner().invoke(status_cmd, list(args), obj=self.app, catch_exceptions=False)

    def test_json_lists_pending_cleanup(self):
        result = self._invoke("--json", pending=[self.pending])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        doc = json.loads(result.output)
        self.assertEqual(doc["removed_connector_cleanup"][0]["items"][0]["path"], _CONFIG)

    def test_json_has_no_key_when_nothing_is_pending(self):
        doc = json.loads(self._invoke("--json").output)
        self.assertNotIn("removed_connector_cleanup", doc)

    def test_human_status_points_at_doctor(self):
        result = self._invoke(pending=[self.pending])
        self.assertIn("OmniGent was removed in 1.0.4; 1 file(s) to clean up by hand", result.output)
        self.assertIn("defenseclaw doctor", result.output)
        self.assertNotIn("to clean up by hand", self._invoke().output)


if __name__ == "__main__":
    unittest.main()
