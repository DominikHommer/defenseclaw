# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0568: defaults never select an OpenClaw the user does not have.

A plain ``defenseclaw init`` (no terminal, no flags) on a fresh account wrote a
config without a ``claw`` block, so every later load named OpenClaw through the
``claw.mode`` default: the gateway watched ``~/.openclaw`` folders it created,
and ``uninstall --all`` planned and ran an OpenClaw teardown. Configs an older
release wrote that way get the same answer from the uninstall plan.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands import cmd_uninstall
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.context import AppContext


class _FreshHome(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="dclaw-gap0568-")))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / "home"
        self.data_dir = self.home / ".defenseclaw"
        self.home.mkdir()
        for patcher in (
            patch.dict(os.environ, {"HOME": str(self.home), "USERPROFILE": str(self.home)}),
            patch("defenseclaw.config.default_data_path", return_value=self.data_dir),
            patch("defenseclaw.openclaw_presence.openclaw_binary_installed", return_value=False),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _plant_openclaw(self) -> None:
        config = self.home / ".openclaw" / "openclaw.json"
        config.parent.mkdir(parents=True)
        config.write_text("{}\n", encoding="utf-8")

    def _legacy_init(self):
        with (
            patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None),
            patch("defenseclaw.commands.cmd_init._install_guardrail"),
            patch("defenseclaw.commands.cmd_init._install_scanners"),
            patch("defenseclaw.commands.cmd_init._start_gateway"),
            patch("defenseclaw.commands.cmd_init._stdin_is_tty", return_value=False),
        ):
            result = CliRunner().invoke(init_cmd, ["--skip-install"], obj=AppContext())
        self.assertEqual(result.exit_code, 0, result.output)
        return result

    def _plan(self):
        return cmd_uninstall._build_plan(wipe_data=True, binaries=False, revert_openclaw=True, remove_plugin=True)


class FreshInitWithoutOpenClawTests(_FreshHome):
    def test_init_without_openclaw_selects_no_connector(self):
        from defenseclaw.config import load

        result = self._legacy_init()
        cfg = load()

        self.assertFalse(cfg.has_connector_configured())
        self.assertEqual(cfg.active_connectors(), [])
        self.assertNotIn("connector: openclaw", result.output)
        self.assertNotIn(".openclaw", result.output)

    def test_uninstall_after_init_without_openclaw_plans_no_openclaw_teardown(self):
        self._legacy_init()
        plan = self._plan()

        self.assertEqual(plan.connector, "")
        self.assertEqual(plan.connectors, ())
        self.assertFalse(plan.revert_openclaw)
        self.assertFalse(plan.remove_plugin)
        self.assertEqual(plan.openclaw_config_file, "")
        self.assertEqual(plan.openclaw_home, "")

    def test_init_with_openclaw_installed_keeps_the_openclaw_default(self):
        from defenseclaw.config import load

        self._plant_openclaw()
        self._legacy_init()

        self.assertEqual(load().active_connectors(), ["openclaw"])
        self.assertIn("openclaw", self._plan().connectors)


class OlderConfigWithoutClawBlockTests(_FreshHome):
    """A config an older init wrote with no claw block (upgrade path)."""

    def setUp(self) -> None:
        super().setUp()
        from defenseclaw.config import CURRENT_CONFIG_VERSION

        self.data_dir.mkdir(parents=True)
        (self.data_dir / "config.yaml").write_text(
            f"config_version: {CURRENT_CONFIG_VERSION}\nobservability: {{}}\n", encoding="utf-8"
        )

    def test_load_without_openclaw_selects_no_connector(self):
        from defenseclaw.config import load

        cfg = load()

        self.assertFalse(cfg.has_connector_configured())
        self.assertEqual(cfg.active_connectors(), [])

    def test_load_with_openclaw_installed_keeps_openclaw(self):
        from defenseclaw.config import load

        self._plant_openclaw()

        self.assertEqual(load().active_connectors(), ["openclaw"])

    def test_a_connector_set_after_load_is_configured(self):
        from defenseclaw.config import load

        cfg = load()
        cfg.claw.mode = "codex"

        self.assertEqual(cfg.active_connectors(), ["codex"])

    def test_uninstall_plans_no_openclaw_teardown_without_openclaw(self):
        plan = self._plan()

        self.assertEqual(plan.connectors, ())
        self.assertFalse(plan.revert_openclaw)
        self.assertEqual(plan.openclaw_home, "")

    def test_uninstall_still_tears_down_an_installed_openclaw(self):
        self._plant_openclaw()

        plan = self._plan()

        self.assertEqual(plan.connectors, ("openclaw",))
        self.assertTrue(plan.revert_openclaw)

    def test_uninstall_still_tears_down_openclaw_with_a_backup_marker(self):
        marker = self.data_dir / "connector_backups" / "openclaw" / "openclaw.json.json"
        marker.parent.mkdir(parents=True)
        marker.write_text("{}", encoding="utf-8")

        self.assertIn("openclaw", self._plan().connectors)


class OlderInitClawModeTests(OlderConfigWithoutClawBlockTests):
    """The claw.mode openclaw default an init before 1.0.4 saved (upgrade path)."""

    def setUp(self) -> None:
        super().setUp()
        from defenseclaw.config import CURRENT_CONFIG_VERSION

        (self.data_dir / "config.yaml").write_text(
            f"config_version: {CURRENT_CONFIG_VERSION}\nclaw:\n  mode: openclaw\n"
            "  home_dir: ~/.openclaw\n  config_file: ~/.openclaw/openclaw.json\n",
            encoding="utf-8",
        )


class FirstRunDefaultConnectorTests(unittest.TestCase):
    """init --yes / --non-interactive and the prompt pick no absent agent."""

    @staticmethod
    def _discovery(**installed: bool):
        from types import SimpleNamespace

        return SimpleNamespace(agents={name: SimpleNamespace(installed=flag) for name, flag in installed.items()})

    def _default(self, disc) -> str:
        from defenseclaw.commands.cmd_init import _normalize_connector_arg

        with patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents", return_value=disc):
            return _normalize_connector_arg(None, discover_default=True)

    def test_nothing_installed_defaults_to_no_connector(self):
        self.assertEqual(self._default(self._discovery(codex=False, claudecode=False)), "none")

    def test_failed_discovery_defaults_to_no_connector(self):
        from defenseclaw.commands.cmd_init import _normalize_connector_arg

        with patch("defenseclaw.commands.cmd_init.agent_discovery.discover_agents", side_effect=OSError("scan")):
            self.assertEqual(_normalize_connector_arg(None, discover_default=True), "none")

    def test_an_installed_agent_is_still_picked(self):
        self.assertEqual(self._default(self._discovery(codex=False, claudecode=True)), "claudecode")
        self.assertEqual(self._default(self._discovery(codex=True, claudecode=True)), "codex")

    def test_explicit_codex_still_works(self):
        from defenseclaw.commands.cmd_init import _normalize_connector_arg

        self.assertEqual(_normalize_connector_arg("codex"), "codex")

class SetupMenuDefaultTests(unittest.TestCase):
    """The setup connector menu defaults only to an installed agent."""

    def _menu_default(self, current: str, installed: list[str], picked: str | None):
        from defenseclaw.commands import cmd_setup

        with (
            patch.object(cmd_setup, "_detect_installed_connectors", return_value=installed),
            patch.object(cmd_setup, "_read_picked_connector", return_value=picked),
            patch.object(cmd_setup.click, "prompt", return_value=1) as prompt,
        ):
            cmd_setup._select_connector_interactive(current, data_dir="/unused")
        default = prompt.call_args.kwargs["default"]
        return None if default is None else cmd_setup._CONNECTOR_NAMES[default - 1]

    def test_no_installed_agent_has_no_default(self):
        self.assertIsNone(self._menu_default("openclaw", [], None))
        self.assertIsNone(self._menu_default("", [], None))

    def test_a_picked_agent_that_is_not_installed_is_not_the_default(self):
        # An older installer recorded codex when it had no terminal to ask on.
        self.assertIsNone(self._menu_default("openclaw", [], "codex"))
        self.assertEqual(self._menu_default("openclaw", ["claudecode"], "codex"), "claudecode")

    def test_an_installed_agent_is_the_default(self):
        self.assertEqual(self._menu_default("openclaw", ["claudecode", "codex"], "codex"), "codex")
        self.assertEqual(self._menu_default("openclaw", ["claudecode"], None), "claudecode")
        self.assertEqual(self._menu_default("openclaw", ["openclaw"], None), "openclaw")

    def test_a_configured_connector_stays_the_default(self):
        self.assertEqual(self._menu_default("cursor", [], None), "cursor")


if __name__ == "__main__":
    unittest.main()
